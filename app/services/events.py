import logging

logger = logging.getLogger(__name__)

class EventBus:
    """
    A lightweight, in-memory event dispatcher that enables loose coupling between
    the core business routes and secondary modules (telemetry, ML risk scoring, email alerts).
    """
    def __init__(self):
        self._listeners = {}

    def subscribe(self, event_name, callback):
        """
        Subscribe a callback function to a specific event.
        
        Args:
            event_name (str): The name/topic of the event.
            callback (callable): The function to invoke when the event is triggered.
        """
        if event_name not in self._listeners:
            self._listeners[event_name] = []
        self._listeners[event_name].append(callback)
        logger.info(f"Subscribed {callback.__name__} to event: {event_name}")

    def dispatch(self, event_name, *args, **kwargs):
        """
        Trigger an event and notify all subscribed callbacks.
        If a callback throws an error, it is caught and logged so the main request flow is not disrupted.
        
        Args:
            event_name (str): The name/topic of the event.
            *args: Positional arguments to pass to the callback.
            **kwargs: Keyword arguments to pass to the callback.
        """
        if event_name in self._listeners:
            for callback in self._listeners[event_name]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Error running listener {callback.__name__} for event '{event_name}': {e}", exc_info=True)

# Global singleton event bus
event_bus = EventBus()
