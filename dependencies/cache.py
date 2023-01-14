from collections import OrderedDict
import time


class Cache:
    def __init__(self, max_size=1000):
        self.cache = OrderedDict()
        self.max_size = max_size

    def get(self, key):
        if key in self.cache:
            value = self.cache.pop(key)
            self.cache[key] = value
            return value
        else:
            return None, None

    def set(self, key, value):
        if key in self.cache:
            self.cache.pop(key)
        else:
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
        self.cache[key] = value


class TimeLimitedCache(Cache):
    def __init__(self, max_size=1000, expiration_time=60):
        super().__init__(max_size)
        self.expiration_time = expiration_time

    def get(self, key):
        value, timestamp = super().get(key)
        if not value:
            return None
        elif time.time() - timestamp > self.expiration_time:
            self.cache.pop(key)
            return None
        else:
            return value

    def set(self, key, value):
        super().set(key, (value, time.time()))