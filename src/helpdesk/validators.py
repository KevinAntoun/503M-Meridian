# validators.py
#
# validators for file uploads, etc.

from django.utils.translation import gettext as _

from helpdesk import settings as helpdesk_settings

# TODO: can we use the builtin Django validator instead?
# see:
# https://docs.djangoproject.com/en/4.0/ref/validators/#fileextensionvalidator

import warnings
from io import BytesIO

from django.core.files.base import ContentFile
from PIL import Image, UnidentifiedImageError
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _f
import logging

logger = logging.getLogger(__name__)


def validate_file_extension(value):
    if not helpdesk_settings.HELPDESK_VALIDATE_ATTACHMENT_TYPES:
        logger.warning(
            "attachment_rejected check=validation_disabled"
        )
        raise ValidationError(
            _("Attachment rejected."),
            code="validation_disabled",
        )

    filename = getattr(value, "name", None)

    if (
        not isinstance(filename, str)
        or len(filename) > 255
        or filename.count(".") != 1
        or "/" in filename
        or "\\" in filename
        or ":" in filename
        or any(ord(c) < 32 or ord(c) == 127 for c in filename)
    ):
        logger.warning(
            "attachment_rejected check=invalid_filename"
        )
        raise ValidationError(
            _("Attachment rejected."),
            code="invalid_filename",
        )

    name, extension = filename.rsplit(".", 1)

    allowed = {
        ext.lower()
        for ext in helpdesk_settings.HELPDESK_VALID_EXTENSIONS
    }

    if not name or f".{extension.lower()}" not in allowed:
        logger.warning(
            "attachment_rejected check=invalid_extension"
        )
        raise ValidationError(
            _("Attachment rejected."),
            code="invalid_extension",
        )


MAX_FILE_BYTES = 8 * 1024 * 1024  # 8 MiB
MAX_IMAGE_PIXELS = 12_000_000

Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


def sanitize_attachment(uploaded):
    # Validate the filename before processing.
    validate_file_extension(uploaded)

    if not 0 < uploaded.size <= MAX_FILE_BYTES:
        raise ValidationError(
            _("Attachment rejected."),
            code="file_size",
        )

    extension = uploaded.name.rsplit(".", 1)[1].lower()

    formats = {
        "png": ("PNG", "image/png"),
        "jpg": ("JPEG", "image/jpeg"),
        "jpeg": ("JPEG", "image/jpeg"),
    }

    if extension not in formats:
        raise ValidationError(
            _("Attachment rejected."),
            code="invalid_type",
        )

    expected_format, detected_type = formats[extension]

    try:
        uploaded.seek(0)

        with warnings.catch_warnings():
            warnings.simplefilter(
                "error",
                Image.DecompressionBombWarning,
            )

            with Image.open(uploaded) as image:
                if image.format != expected_format:
                    raise ValidationError(
                        _("Attachment rejected."),
                        code="type_mismatch",
                    )

                if image.width * image.height > MAX_IMAGE_PIXELS:
                    raise ValidationError(
                        _("Attachment rejected."),
                        code="pixel_limit",
                    )

                if getattr(image, "n_frames", 1) != 1:
                    raise ValidationError(
                        _("Attachment rejected."),
                        code="multiple_frames",
                    )

                image.load()

                has_alpha = (
                    "A" in image.getbands()
                    or "transparency" in image.info
                )
                mode = (
                    "RGBA"
                    if expected_format == "PNG" and has_alpha
                    else "RGB"
                )

                pixels = image.convert(mode)

                # Fresh image: copy pixels, not metadata.
                clean_image = Image.new(mode, image.size)
                clean_image.paste(pixels)

        output = BytesIO()
        clean_image.save(output, format=expected_format)

        if output.tell() > MAX_FILE_BYTES:
            raise ValidationError(
                _("Attachment rejected."),
                code="encoded_size",
            )

        return (
            ContentFile(
                output.getvalue(),
                name=uploaded.name,
            ),
            detected_type,
        )

    except ValidationError:
        raise
    except (
        UnidentifiedImageError,
        OSError,
        ValueError,
        SyntaxError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ):
        raise ValidationError(
            _("Attachment rejected."),
            code="invalid_image",
        ) from None
