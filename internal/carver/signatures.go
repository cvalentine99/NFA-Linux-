// Package carver provides file signature definitions for magic byte detection.
package carver

// defaultSignatures returns the default set of file signatures for carving.
func defaultSignatures() []*FileSignature {
	return []*FileSignature{
		// Images
		{
			Name:      "JPEG Image",
			Extension: ".jpg",
			MIMEType:  "image/jpeg",
			Header:    []byte{0xFF, 0xD8, 0xFF},
			HeaderHex: "FFD8FF",
			Footer:    []byte{0xFF, 0xD9},
			FooterHex: "FFD9",
			MaxSize:   50 * 1024 * 1024, // 50MB
			Category:  "image",
			Dangerous: false,
		},
		{
			Name:      "PNG Image",
			Extension: ".png",
			MIMEType:  "image/png",
			Header:    []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			HeaderHex: "89504E470D0A1A0A",
			Footer:    []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82},
			FooterHex: "49454E44AE426082",
			MaxSize:   50 * 1024 * 1024,
			Category:  "image",
			Dangerous: false,
		},
		{
			Name:      "GIF Image",
			Extension: ".gif",
			MIMEType:  "image/gif",
			Header:    []byte{0x47, 0x49, 0x46, 0x38},
			HeaderHex: "47494638",
			Footer:    []byte{0x00, 0x3B},
			FooterHex: "003B",
			MaxSize:   20 * 1024 * 1024,
			Category:  "image",
			Dangerous: false,
		},
		{
			Name:      "WebP Image",
			Extension: ".webp",
			MIMEType:  "image/webp",
			Header:    []byte{0x52, 0x49, 0x46, 0x46}, // RIFF
			HeaderHex: "52494646",
			MaxSize:   50 * 1024 * 1024,
			Category:  "image",
			Dangerous: false,
		},
		{
			Name:      "BMP Image",
			Extension: ".bmp",
			MIMEType:  "image/bmp",
			Header:    []byte{0x42, 0x4D},
			HeaderHex: "424D",
			MaxSize:   50 * 1024 * 1024,
			Category:  "image",
			Dangerous: false,
		},
		{
			Name:      "TIFF Image (Little Endian)",
			Extension: ".tiff",
			MIMEType:  "image/tiff",
			Header:    []byte{0x49, 0x49, 0x2A, 0x00},
			HeaderHex: "49492A00",
			MaxSize:   100 * 1024 * 1024,
			Category:  "image",
			Dangerous: false,
		},
		{
			Name:      "TIFF Image (Big Endian)",
			Extension: ".tiff",
			MIMEType:  "image/tiff",
			Header:    []byte{0x4D, 0x4D, 0x00, 0x2A},
			HeaderHex: "4D4D002A",
			MaxSize:   100 * 1024 * 1024,
			Category:  "image",
			Dangerous: false,
		},
		{
			Name:      "ICO Icon",
			Extension: ".ico",
			MIMEType:  "image/x-icon",
			Header:    []byte{0x00, 0x00, 0x01, 0x00},
			HeaderHex: "00000100",
			MaxSize:   1 * 1024 * 1024,
			Category:  "image",
			Dangerous: false,
		},

		// Documents
		{
			Name:      "PDF Document",
			Extension: ".pdf",
			MIMEType:  "application/pdf",
			Header:    []byte{0x25, 0x50, 0x44, 0x46},
			HeaderHex: "25504446",
			Footer:    []byte{0x25, 0x25, 0x45, 0x4F, 0x46},
			FooterHex: "2525454F46",
			MaxSize:   500 * 1024 * 1024,
			Category:  "document",
			Dangerous: false,
		},
		{
			Name:      "Microsoft Office Document (OOXML)",
			Extension: ".docx",
			MIMEType:  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			Header:    []byte{0x50, 0x4B, 0x03, 0x04},
			HeaderHex: "504B0304",
			MaxSize:   100 * 1024 * 1024,
			Category:  "document",
			Dangerous: false,
		},
		{
			Name:      "Microsoft Office Document (OLE)",
			Extension: ".doc",
			MIMEType:  "application/msword",
			Header:    []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
			HeaderHex: "D0CF11E0A1B11AE1",
			MaxSize:   100 * 1024 * 1024,
			Category:  "document",
			Dangerous: false,
		},
		{
			Name:      "Rich Text Format",
			Extension: ".rtf",
			MIMEType:  "application/rtf",
			Header:    []byte{0x7B, 0x5C, 0x72, 0x74, 0x66},
			HeaderHex: "7B5C727466",
			MaxSize:   50 * 1024 * 1024,
			Category:  "document",
			Dangerous: false,
		},

		// Archives
		{
			Name:      "ZIP Archive",
			Extension: ".zip",
			MIMEType:  "application/zip",
			Header:    []byte{0x50, 0x4B, 0x03, 0x04},
			HeaderHex: "504B0304",
			MaxSize:   500 * 1024 * 1024,
			Category:  "archive",
			Dangerous: false,
		},
		{
			Name:      "RAR Archive",
			Extension: ".rar",
			MIMEType:  "application/x-rar-compressed",
			Header:    []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07},
			HeaderHex: "526172211A07",
			MaxSize:   500 * 1024 * 1024,
			Category:  "archive",
			Dangerous: false,
		},
		{
			Name:      "7-Zip Archive",
			Extension: ".7z",
			MIMEType:  "application/x-7z-compressed",
			Header:    []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
			HeaderHex: "377ABCAF271C",
			MaxSize:   500 * 1024 * 1024,
			Category:  "archive",
			Dangerous: false,
		},
		{
			Name:      "GZIP Archive",
			Extension: ".gz",
			MIMEType:  "application/gzip",
			Header:    []byte{0x1F, 0x8B, 0x08},
			HeaderHex: "1F8B08",
			MaxSize:   500 * 1024 * 1024,
			Category:  "archive",
			Dangerous: false,
		},
		{
			Name:      "TAR Archive",
			Extension: ".tar",
			MIMEType:  "application/x-tar",
			Header:    []byte{0x75, 0x73, 0x74, 0x61, 0x72},
			HeaderHex: "7573746172",
			MaxSize:   500 * 1024 * 1024,
			Category:  "archive",
			Dangerous: false,
		},
		{
			Name:      "BZIP2 Archive",
			Extension: ".bz2",
			MIMEType:  "application/x-bzip2",
			Header:    []byte{0x42, 0x5A, 0x68},
			HeaderHex: "425A68",
			MaxSize:   500 * 1024 * 1024,
			Category:  "archive",
			Dangerous: false,
		},
		{
			Name:      "XZ Archive",
			Extension: ".xz",
			MIMEType:  "application/x-xz",
			Header:    []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00},
			HeaderHex: "FD377A585A00",
			MaxSize:   500 * 1024 * 1024,
			Category:  "archive",
			Dangerous: false,
		},

		// Executables (Dangerous)
		{
			Name:      "Windows Executable (PE)",
			Extension: ".exe",
			MIMEType:  "application/x-dosexec",
			Header:    []byte{0x4D, 0x5A},
			HeaderHex: "4D5A",
			MaxSize:   100 * 1024 * 1024,
			Category:  "executable",
			Dangerous: true,
		},
		{
			Name:      "Linux Executable (ELF)",
			Extension: ".elf",
			MIMEType:  "application/x-executable",
			Header:    []byte{0x7F, 0x45, 0x4C, 0x46},
			HeaderHex: "7F454C46",
			MaxSize:   100 * 1024 * 1024,
			Category:  "executable",
			Dangerous: true,
		},
		{
			Name:      "macOS Executable (Mach-O 64-bit)",
			Extension: ".macho",
			MIMEType:  "application/x-mach-binary",
			Header:    []byte{0xCF, 0xFA, 0xED, 0xFE},
			HeaderHex: "CFFAEDFE",
			MaxSize:   100 * 1024 * 1024,
			Category:  "executable",
			Dangerous: true,
		},
		{
			Name:      "macOS Executable (Mach-O 32-bit)",
			Extension: ".macho",
			MIMEType:  "application/x-mach-binary",
			Header:    []byte{0xCE, 0xFA, 0xED, 0xFE},
			HeaderHex: "CEFAEDFE",
			MaxSize:   100 * 1024 * 1024,
			Category:  "executable",
			Dangerous: true,
		},
		{
			Name:      "Windows DLL",
			Extension: ".dll",
			MIMEType:  "application/x-msdownload",
			Header:    []byte{0x4D, 0x5A},
			HeaderHex: "4D5A",
			MaxSize:   100 * 1024 * 1024,
			Category:  "executable",
			Dangerous: true,
		},
		{
			Name:      "Java Class File",
			Extension: ".class",
			MIMEType:  "application/java-vm",
			Header:    []byte{0xCA, 0xFE, 0xBA, 0xBE},
			HeaderHex: "CAFEBABE",
			MaxSize:   10 * 1024 * 1024,
			Category:  "executable",
			Dangerous: true,
		},
		{
			Name:      "WebAssembly",
			Extension: ".wasm",
			MIMEType:  "application/wasm",
			Header:    []byte{0x00, 0x61, 0x73, 0x6D},
			HeaderHex: "0061736D",
			MaxSize:   50 * 1024 * 1024,
			Category:  "executable",
			Dangerous: true,
		},

		// Media - Audio
		{
			Name:      "MP3 Audio",
			Extension: ".mp3",
			MIMEType:  "audio/mpeg",
			Header:    []byte{0xFF, 0xFB},
			HeaderHex: "FFFB",
			MaxSize:   100 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},
		{
			Name:      "MP3 Audio (ID3v2)",
			Extension: ".mp3",
			MIMEType:  "audio/mpeg",
			Header:    []byte{0x49, 0x44, 0x33},
			HeaderHex: "494433",
			MaxSize:   100 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},
		{
			Name:      "WAV Audio",
			Extension: ".wav",
			MIMEType:  "audio/wav",
			Header:    []byte{0x52, 0x49, 0x46, 0x46},
			HeaderHex: "52494646",
			MaxSize:   500 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},
		{
			Name:      "FLAC Audio",
			Extension: ".flac",
			MIMEType:  "audio/flac",
			Header:    []byte{0x66, 0x4C, 0x61, 0x43},
			HeaderHex: "664C6143",
			MaxSize:   500 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},
		{
			Name:      "OGG Audio",
			Extension: ".ogg",
			MIMEType:  "audio/ogg",
			Header:    []byte{0x4F, 0x67, 0x67, 0x53},
			HeaderHex: "4F676753",
			MaxSize:   100 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},

		// Media - Video
		{
			Name:      "MP4 Video",
			Extension: ".mp4",
			MIMEType:  "video/mp4",
			Header:    []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70},
			HeaderHex: "0000001866747970",
			MaxSize:   2 * 1024 * 1024 * 1024, // 2GB
			Category:  "media",
			Dangerous: false,
		},
		{
			Name:      "AVI Video",
			Extension: ".avi",
			MIMEType:  "video/x-msvideo",
			Header:    []byte{0x52, 0x49, 0x46, 0x46},
			HeaderHex: "52494646",
			MaxSize:   2 * 1024 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},
		{
			Name:      "MKV Video",
			Extension: ".mkv",
			MIMEType:  "video/x-matroska",
			Header:    []byte{0x1A, 0x45, 0xDF, 0xA3},
			HeaderHex: "1A45DFA3",
			MaxSize:   2 * 1024 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},
		{
			Name:      "WebM Video",
			Extension: ".webm",
			MIMEType:  "video/webm",
			Header:    []byte{0x1A, 0x45, 0xDF, 0xA3},
			HeaderHex: "1A45DFA3",
			MaxSize:   2 * 1024 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},
		{
			Name:      "FLV Video",
			Extension: ".flv",
			MIMEType:  "video/x-flv",
			Header:    []byte{0x46, 0x4C, 0x56, 0x01},
			HeaderHex: "464C5601",
			MaxSize:   500 * 1024 * 1024,
			Category:  "media",
			Dangerous: false,
		},

		// Other
		{
			Name:      "SQLite Database",
			Extension: ".sqlite",
			MIMEType:  "application/x-sqlite3",
			Header:    []byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00},
			HeaderHex: "53514C69746520666F726D6174203300",
			MaxSize:   1 * 1024 * 1024 * 1024,
			Category:  "database",
			Dangerous: false,
		},
		{
			Name:      "XML Document",
			Extension: ".xml",
			MIMEType:  "application/xml",
			Header:    []byte{0x3C, 0x3F, 0x78, 0x6D, 0x6C},
			HeaderHex: "3C3F786D6C",
			MaxSize:   100 * 1024 * 1024,
			Category:  "document",
			Dangerous: false,
		},
		{
			Name:      "HTML Document",
			Extension: ".html",
			MIMEType:  "text/html",
			Header:    []byte{0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45},
			HeaderHex: "3C21444F43545950",
			MaxSize:   50 * 1024 * 1024,
			Category:  "document",
			Dangerous: false,
		},
		{
			Name:      "Certificate (DER)",
			Extension: ".cer",
			MIMEType:  "application/x-x509-ca-cert",
			Header:    []byte{0x30, 0x82},
			HeaderHex: "3082",
			MaxSize:   1 * 1024 * 1024,
			Category:  "certificate",
			Dangerous: false,
		},
	}
}

// GetSignatureByExtension returns a signature by file extension.
func GetSignatureByExtension(ext string) *FileSignature {
	for _, sig := range defaultSignatures() {
		if sig.Extension == ext {
			return sig
		}
	}
	return nil
}

// GetSignatureByMIME returns a signature by MIME type.
func GetSignatureByMIME(mimeType string) *FileSignature {
	for _, sig := range defaultSignatures() {
		if sig.MIMEType == mimeType {
			return sig
		}
	}
	return nil
}

// GetDangerousSignatures returns all signatures marked as dangerous.
func GetDangerousSignatures() []*FileSignature {
	var dangerous []*FileSignature
	for _, sig := range defaultSignatures() {
		if sig.Dangerous {
			dangerous = append(dangerous, sig)
		}
	}
	return dangerous
}

// GetSignaturesByCategory returns all signatures for a category.
func GetSignaturesByCategory(category string) []*FileSignature {
	var sigs []*FileSignature
	for _, sig := range defaultSignatures() {
		if sig.Category == category {
			sigs = append(sigs, sig)
		}
	}
	return sigs
}
