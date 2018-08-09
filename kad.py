def distance(x, y):
    return x ^ y


def highest_bit(x):
    if x == 0:
        return -1

    result = 0
    while x != 1:
        x >>= 1
        result += 1
    return result


class KBucket:
    def __init__(self, k, key_length, key):
        assert k > 0
        self.k = k
        self.key = key
        self.key_length = key_length
        assert key_length > 0
        self._check_key(key)
        self.buckets = [[] for _ in range(key_length + 1)]

    def _get_bucket(self, key):
        d = distance(key, self.key)
        if d != 0:
            return self.buckets[highest_bit(d)]
        else:
            return self.buckets[-1]

    def _check_key(self, key):
        assert 0 <= key < (1 << self.key_length)

    def add(self, key, value):
        self._check_key(key)
        bucket = self._get_bucket(key)
        for i, (k, v) in enumerate(bucket):
            if k == key:
                break
        else:
            if len(bucket) == self.k:
                bucket.pop(0)
            bucket.append((key, value))
            return
        del bucket[i]
        bucket.append((key, value))

    def remove(self, key):
        self._check_key(key)
        bucket = self._get_bucket(key)
        for i, (k, v) in enumerate(bucket):
            if k == key:
                break
        else:
            return
        del bucket[i]

    def get(self, key, default=None):
        self._check_key(key)
        bucket = self._get_bucket(key)
        for i, (k, v) in enumerate(bucket):
            if k == key:
                break
        else:
            return default
        return v

    def __contains__(self, key):
        return self.get(key) is not None

    def find_nodes(self, key):
        self._check_key(key)
        bucket = self._get_bucket(key)
        return bucket[:]

    def keys(self):
        for bucket in self.buckets:
            for k, v in bucket:
                yield k

    def values(self):
        for bucket in self.buckets:
            for k, v in bucket:
                yield v

    def items(self):
        for bucket in self.buckets:
            for k, v in bucket:
                yield k, v

    def __iter__(self):
        return self.items()

    def __str__(self):
        return 'KBucket<{}>'.format(', '.join((str(x) for x in self.buckets)))
