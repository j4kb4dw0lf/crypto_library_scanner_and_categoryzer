import os
import subprocess
import logging

logger = logging.getLogger(__name__)

EXTERNAL_LIBS_DIR = "external_libs"

def clone_external_lib(external_lib_path: str, base_dir: str = EXTERNAL_LIBS_DIR) -> tuple[str | None, str]:
    lib_name = os.path.basename(os.path.normpath(external_lib_path))
    local_path = os.path.join(base_dir, lib_name)

    if os.path.exists(local_path):
        logger.info(f"Library '{lib_name}' already exists at '{local_path}'. Skipping copy.")
        return local_path, lib_name

    os.makedirs(base_dir, exist_ok=True)

    logger.info(f"Copying '{external_lib_path}' to '{local_path}'...")
    try:
        import shutil
        shutil.copytree(external_lib_path, local_path)
        logger.info(f"Successfully copied '{lib_name}'.")
        return local_path, lib_name
    except FileNotFoundError:
        logger.error(f"Source path '{external_lib_path}' does not exist.")
        return None, lib_name
    except PermissionError:
        logger.error(f"Permission denied while copying '{external_lib_path}' to '{local_path}'.")
        return None, lib_name
    except Exception as e:
        logger.error(f"An unexpected error occurred during copying of '{external_lib_path}': {e}", exc_info=True)
        return None, lib_name
