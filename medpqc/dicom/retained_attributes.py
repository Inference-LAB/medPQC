"""
medpqc.dicom.retained_attributes
================================
Default-deny allow-list for DICOM technical and presentation headers.
Any DICOM element not present in RETAINED_ATTRIBUTES is stripped from the
cleartext DICOM envelope during encryption and sealed exclusively inside
the authenticated cryptographic payload.
"""

RETAINED_ATTRIBUTES: frozenset[str] = frozenset(
    {
        # File Meta Information Group 0x0002
        "FileMetaInformationGroupLength",
        "FileMetaInformationVersion",
        "MediaStorageSOPClassUID",
        "MediaStorageSOPInstanceUID",
        "TransferSyntaxUID",
        "ImplementationClassUID",
        "ImplementationVersionName",
        "SourceApplicationEntityTitle",
        # Essential Identification & Routing
        "SOPClassUID",
        "SOPInstanceUID",
        "StudyInstanceUID",
        "SeriesInstanceUID",
        "FrameOfReferenceUID",
        "Modality",
        "PatientID",
        "PatientName",
        # Image Geometry / Technical Presentation
        "Rows",
        "Columns",
        "BitsAllocated",
        "BitsStored",
        "HighBit",
        "PixelRepresentation",
        "SamplesPerPixel",
        "PhotometricInterpretation",
        "PlanarConfiguration",
        "NumberOfFrames",
        "PixelSpacing",
        "ImagerPixelSpacing",
        "PixelAspectRatio",
        "WindowCenter",
        "WindowWidth",
        "RescaleIntercept",
        "RescaleSlope",
        "RescaleType",
        # Non-diagnostic container indicators
        "ImageType",
        "LossyImageCompression",
        "ImageComments",
        # Standard Private framing tags
        "PrivateCreator",
    }
)

__all__ = ["RETAINED_ATTRIBUTES"]
