from PIL import Image, ExifTags, UnidentifiedImageError
from app.models import database, models
import json


def normalize_direction(direction):
    if isinstance(direction, bytes):
        direction = direction.decode("utf-8", errors="ignore")

    if isinstance(direction, str):
        return direction.strip().upper()

    return None


def convert(dms, direction, coordinate_type):
    if dms is None or direction is None:
        return None

    try:
        direction = normalize_direction(direction)

        degrees = float(dms[0])
        minutes = float(dms[1])
        seconds = float(dms[2])

        if minutes < 0 or minutes >= 60:
            return None

        if seconds < 0 or seconds >= 60:
            return None

        if coordinate_type == "latitude":
            if degrees < 0 or degrees > 90:
                return None

            valid_directions = {"N", "S"}

        elif coordinate_type == "longitude":
            if degrees < 0 or degrees > 180:
                return None

            valid_directions = {"E", "W"}

        else:
            return None

        if direction not in valid_directions:
            return None

        decimal = degrees + (minutes / 60) + (seconds / 3600)

        if direction in {"S", "W"}:
            decimal = -decimal

        return decimal

    except (IndexError, TypeError, ValueError, ZeroDivisionError):
        return None


def get_metadata(user_inp):
    metadata = {}

    try:
        with Image.open(user_inp) as img:
            exif_raw = img.getexif()

            if not exif_raw:
                print("No EXIF metadata found.")
                return {}

            # Extract standard EXIF metadata
            for tag_id, value in exif_raw.items():
                tag_name = ExifTags.TAGS.get(tag_id, tag_id)

                if tag_name == "GPSInfo":
                    continue

                metadata[tag_name] = value

            # Extract GPS metadata separately
            gps_raw = exif_raw.get_ifd(0x8825)

            if not gps_raw:
                print("No GPS entries found.")
                return metadata

            gps_dict = {}

            for tag_id, value in gps_raw.items():
                tag_name = ExifTags.GPSTAGS.get(tag_id, tag_id)
                gps_dict[tag_name] = value

            latitude = gps_dict.get("GPSLatitude")
            latitude_ref = gps_dict.get("GPSLatitudeRef")
            longitude = gps_dict.get("GPSLongitude")
            longitude_ref = gps_dict.get("GPSLongitudeRef")

            if (
                latitude is not None
                and latitude_ref is not None
                and longitude is not None
                and longitude_ref is not None
            ):
                decimal_latitude = convert(
                    latitude,
                    latitude_ref,
                    "latitude"
                )

                decimal_longitude = convert(
                    longitude,
                    longitude_ref,
                    "longitude"
                )

                if (
                    decimal_latitude is not None
                    and decimal_longitude is not None
                ):
                    gps_dict["DecimalLatitude"] = decimal_latitude
                    gps_dict["DecimalLongitude"] = decimal_longitude

            metadata["GPSInfo"] = gps_dict

    except FileNotFoundError:
        print("File does not exist!")

    except (UnidentifiedImageError, OSError):
        print("The file is not a valid or readable image.")

    except Exception as e:
        print(f"Unexpected error has occurred: {e}")

    return metadata

def normalize_value(value):
    if value is None:
        return None
    elif isinstance(value, str) or isinstance(value, int) or isinstance(value, float):
        return value
    elif isinstance(value, dict):
        normal_dict = {}
        for x, y in value.items():
            safe_key = str(x).strip()
            normal_dict[safe_key] = normalize_value(y)
        return normal_dict
    elif isinstance(value, list) or isinstance(value, tuple):
        normal_list = []
        for x in value:
            normal_list.append(normalize_value(x))
        return normal_list
    elif isinstance(value, bytes):
        try: 
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    return str(value)

def metadata_to_findings(metadata_result):
    findings = []
    normal_data = normalize_value(metadata_result)
    data = json.dumps(normal_data)
    findings.append({"module_source": "exif", "data_type": "metadata", "data": data, "source": "pillow"})
    return findings

def full_image_lookup(img_file):
    user_img = get_metadata(img_file)
    if not user_img:
        return None
    findings = metadata_to_findings(user_img)
    with database.SessionLocal() as session:
        inv = models.Investigation(name="img-metadata", target="user_img")
        for f in findings:
            find = models.Finding(module_source=f["module_source"], data_type=f["data_type"], data=f["data"], source=f["source"])
            inv.inv.append(find)
        session.add(inv)
        session.commit()

    
    
