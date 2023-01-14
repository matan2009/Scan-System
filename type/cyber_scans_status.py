from enum import Enum


class CyberScansStatus(Enum):
    Accepted = 0
    Running = 1
    Error = 2
    Complete = 3
    NotFound = 4
