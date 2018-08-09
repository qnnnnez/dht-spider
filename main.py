import os
import asyncio
from btdht import DHTInstance


async def up():
    i = DHTInstance(os.urandom(20), '0.0.0.0', 11451)
    print('listening on {}:{}, my id: {:020X}'.format(i.ip, i.port, i.id))
    await i.async_bind()
    print('bootstrap process start')
    await i.bootstrap([
        ("router.utorrent.com", 6881),
        ("router.bittorrent.com", 6881),
        ("dht.transmissionbt.com", 6881),
        ("dht.aelitis.com", 6881),
        ('127.0.0.1', 6881)
    ])
    print('bootstrap done')
    while True:
        await i.keep_dht()
        await asyncio.sleep(1)


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(up())
    loop.run_forever()


if __name__ == '__main__':
    main()
