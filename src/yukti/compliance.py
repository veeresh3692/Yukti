SUPPORTED_STORAGE = ["HDD", "SSD", "USB", "MemoryCard", "ExternalDrive"]
SUPPORTED_FILESYSTEMS = ["NTFS", "FAT32", "exFAT", "EXT4", "XFS", "APFS", "HFS+"]
SUPPORTED_OPERATING_SYSTEMS = ["Linux", "Windows", "macOS"]

SANITIZATION_STANDARDS = {
    "NIST_800_88_CLEAR": "Single-pass clear operation with verification",
    "NIST_800_88_PURGE": "Enhanced purge operation and verification",
    "DOD_5220_22_M": "Multi-pass overwrite profile",
}

FORENSIC_STANDARDS = {
    "ISO_27037": "Guidelines for identification, collection, acquisition and preservation",
    "ACPO": "Digital evidence handling principles",
}


MEASURABLE_REQUIREMENTS = {
    "drive_eraser": {
        "verification_required": True,
        "tamper_evident_logs": True,
        "profile_based_erasure": True,
    },
    "file_folder_eraser": {
        "batch_mode": True,
        "metadata_cleansing": True,
        "verification_required": True,
    },
    "recovery": {
        "signature_based": True,
        "structure_based": True,
        "metadata_independent": True,
        "fragment_reconstruction": True,
        "confidence_scoring": True,
    },
    "reporting": {
        "centralized_audit": True,
        "exportable_reports": True,
        "integrity_checks": True,
        "role_based_access_model": True,
    },
}
