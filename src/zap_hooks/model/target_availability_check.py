from typing import Optional

from requests import Response, RequestException


class TargetAvailabilityCheck:
    def __init__(
        self,
        is_available: bool,
        response: Optional[Response] = None,
        unavailable_reason: Optional[RequestException] = None,
    ):
        self._is_available = is_available
        self._response = response
        self._unavailable_reason = unavailable_reason

    def status_code(self) -> Optional[int]:
        if self._response is not None:
            return self._response.status_code

        return None

    def is_available(self) -> bool:
        return self._is_available

    def unavailable_reason(self) -> Optional[RequestException]:
        return self._unavailable_reason
