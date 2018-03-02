import asyncio

async def handler(reader, writer):
    magic = await reader.read(6)
    await asyncio.sleep(5)
    print("in five sec!")
    await asyncio.sleep(5)
    writer.write(b'{\n  "r_preimage": "6UNoNhDZ/0awtaDTM7KuCtlYcNkNljscxMLleoJv9+o=",\n  "r_hash": "t7IwR6zq8ZAfHaxvTnPmHdyt9j2tVd9g6TDg59C4juM=",\n  "value": "8192",\n  "settled": true,\n  "creation_date": "1519994196",\n  "settle_date": "1519994199",\n  "payment_request": "lntb81920n1pdfj325pp5k7erq3avatceq8ca43h5uulxrhw2ma3a442a7c8fxrsw059c3m3sdqqcqzysdpwv4dn2xd74lfmea3taxj6pjfxrdl42t8w7ceptgv5ds0td0ypk47llryl6t4a48x54d7mnwremgcmljced4dhwty9g3pfywr307aqpwtkzf4",\n  "expiry": "3600",\n  "cltv_expiry": "144"\n}\n')
    await writer.drain()
    print(magic)

asyncio.ensure_future(asyncio.start_server(handler, "127.0.0.1", 1080))
asyncio.get_event_loop().run_forever()
