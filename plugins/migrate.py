import asyncio
from ia_filterdb import Media, db
import re

async def inspect_and_migrate():
    cursor = Media.find()
    async for doc in cursor:
        print(f"File: {doc.file_name}, Normalized: {doc.normalized_file_name}")
        if not doc.normalized_file_name:
            doc.normalized_file_name = re.sub(r'\s+', ' ', doc.file_name.lower()).strip()
            await doc.commit()
            print(f"Updated normalized_file_name for {doc.file_name}")
    print("Inspection and migration completed.")

asyncio.run(inspect_and_migrate())