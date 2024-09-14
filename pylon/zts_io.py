import asyncio
import logging
import threading
import typing

from pylon.eventloops import LibztSelectorEventLoop

logger = logging.getLogger(__name__)


def new_event_loop():
    loop = LibztSelectorEventLoop()
    asyncio.set_event_loop(loop)
    return loop


class ZtsIoThreadManager:
    def __init__(self, coro: typing.Coroutine):
        """This class must be created in the main loop"""
        self._main_loop = asyncio.get_running_loop()
        self._debug = self._main_loop.get_debug()
        self._zts_loop: asyncio.AbstractEventLoop | None = None
        # ===== these are only accessed from zts_loop
        self._zts_task: asyncio.Task | None = None
        # ===== these are only accessed from main loop
        self._zts_loop_has_started = asyncio.Event()
        # =====

        self._thread = threading.Thread(target=self._io_thread_work, args=(coro,), name='zts_io_thread')

    @property
    def loop(self):
        return self._zts_loop

    def _io_thread_work(self, coro: typing.Coroutine):
        logger.debug('ZTS IO thread starting')
        with asyncio.Runner(loop_factory=new_event_loop, debug=self._debug) as runner:
            try:
                runner.run(self._io_thread_coro(coro))
            except asyncio.CancelledError:
                logger.info('ZTS IO coroutine cancelled')
        logger.debug('ZTS IO thread finishing')

    async def _io_thread_coro(self, coro: typing.Coroutine):
        logger.debug('ZTS IO coroutine starting')
        self._zts_loop = asyncio.get_running_loop()
        self._zts_task = asyncio.current_task()

        self._main_loop.call_soon_threadsafe(self._zts_loop_has_started.set)
        try:
            await coro
        finally:
            self._zts_loop = None
            self._zts_task = None
            logger.debug('ZTS IO coroutine finishing')

    def _cancel_main_task(self):
        if self._zts_task is not None and not self._zts_task.done():
            self._zts_task.cancel()

    async def __aenter__(self):
        """NOTE: this is supposed to run in the main thread's event loop"""
        self._thread.start()
        await self._zts_loop_has_started.wait()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._thread.is_alive():
            if self._zts_loop is not None:
                self._zts_loop.call_soon_threadsafe(self._cancel_main_task)
            await asyncio.to_thread(self._thread.join)
