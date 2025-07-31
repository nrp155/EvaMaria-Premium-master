import logging
from struct import pack
import re
import base64
from pyrogram.file_id import FileId
from pymongo.errors import DuplicateKeyError
from umongo import Instance, Document, fields
from motor.motor_asyncio import AsyncIOMotorClient
from marshmallow.exceptions import ValidationError
from info import DATABASE_URI, DATABASE_NAME, COLLECTION_NAME, USE_CAPTION_FILTER

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

client = AsyncIOMotorClient(DATABASE_URI)
db = client[DATABASE_NAME]
instance = Instance.from_db(db)

@instance.register
class Media(Document):
    file_id = fields.StrField(attribute='_id')
    file_ref = fields.StrField(allow_none=True)
    file_name = fields.StrField(required=True)
    normalized_file_name = fields.StrField(allow_none=True)
    file_size = fields.IntField(required=True)
    file_type = fields.StrField(allow_none=True)
    mime_type = fields.StrField(allow_none=True)
    caption = fields.StrField(allow_none=True)

    class Meta:
        indexes = [
            ('file_name',),
            ('text', 'normalized_file_name'),
        ]
        collection_name = COLLECTION_NAME

async def save_file(media):
    """Save file in database"""
    file_id, file_ref = unpack_new_file_id(media.file_id)
    file_name = media.file_name
    normalized_file_name = re.sub(r'\s+', ' ', media.file_name.lower()).strip()
    
    try:
        file = Media(
            file_id=file_id,
            file_ref=file_ref,
            file_name=file_name,
            normalized_file_name=normalized_file_name,
            file_size=media.file_size,
            file_type=media.file_type,
            mime_type=media.mime_type,
            caption=media.caption.html if media.caption else None,
        )
    except ValidationError:
        logger.exception('Error occurred while saving file in database')
        return False, 2
    else:
        try:
            await file.commit()
        except DuplicateKeyError:      
            logger.warning(
                f'{getattr(media, "file_name", "NO_FILE")} is already saved in database'
            )
            return False, 0
        else:
            logger.info(f'{getattr(media, "file_name", "NO_FILE")} is saved to database')
            return True, 1

async def get_search_results(query, file_type=None, max_results=10, offset=0, filter=False):
    """For given query return (results, next_offset, total_results)"""
    query = re.sub(r'\s+', ' ', query.strip().lower())
    logger.info(f"Processing query: {query}")
    
    # Extract year and remove parentheses/brackets if present
    year_match = re.search(r'\b(19|20)\d{2}\b(?:[\)\]\s]*)?$', query)
    year = year_match.group(1) + year_match.group(2) if year_match else None
    if year:
        query = re.sub(r'\b(19|20)\d{2}\b(?:[\)\]\s]*)?$', '', query).strip()
    
    if not query:
        raw_pattern = '.'
    else:
        # Create regex that matches spaces or hyphens (zero or more), preserves colons
        words = query.split()
        escaped_words = [re.escape(word) for word in words]
        raw_pattern = r'[\s\-]*'.join(escaped_words)
        if year:
            raw_pattern = f"{raw_pattern}(?:[\s\(\[]*{year}[\)\]]*)?"
    
    try:
        regex = re.compile(raw_pattern, flags=re.IGNORECASE)
        logger.info(f"Generated regex: {raw_pattern}")
    except Exception as e:
        logger.error(f"Regex compilation failed for pattern {raw_pattern}: {str(e)}")
        return [], '', 0

    if USE_CAPTION_FILTER:
        filter_dict = {'$or': [
            {'file_name': regex},
            {'normalized_file_name': regex},
            {'caption': regex}
        ]}
    else:
        filter_dict = {'$or': [
            {'file_name': regex},
            {'normalized_file_name': regex}
        ]}

    if file_type:
        filter_dict['file_type'] = file_type

    total_results = await Media.count_documents(filter_dict)
    logger.info(f"Found {total_results} results for query: {query}")
    next_offset = offset + max_results if offset + max_results < total_results else ''

    cursor = Media.find(filter_dict)
    cursor.sort('$natural', -1)
    cursor.skip(offset).limit(max_results)
    files = await cursor.to_list(length=max_results)
    
    if files:
        logger.info(f"Matched files: {[file.file_name for file in files]}")
    else:
        logger.info("No files matched the query.")

    return files, next_offset, total_results

async def get_file_details(query):
    filter = {'file_id': query}
    cursor = Media.find(filter)
    filedetails = await cursor.to_list(length=1)
    return filedetails

def encode_file_id(s: bytes) -> str:
    r = b""
    n = 0
    for i in s + bytes([22]) + bytes([4]):
        if i == 0:
            n += 1
        else:
            if n:
                r += b"\x00" + bytes([n])
                n = 0
            r += bytes([i])
    return base64.urlsafe_b64encode(r).decode().rstrip("=")

def encode_file_ref(file_ref: bytes) -> str:
    return base64.urlsafe_b64encode(file_ref).decode().rstrip("=")

def unpack_new_file_id(new_file_id):
    """Return file_id, file_ref"""
    decoded = FileId.decode(new_file_id)
    file_id = encode_file_id(
        pack(
            "<iiqq",
            int(decoded.file_type),
            decoded.dc_id,
            decoded.media_id,
            decoded.access_hash
        )
    )
    file_ref = encode_file_ref(decoded.file_reference)
    return file_id, file_ref
