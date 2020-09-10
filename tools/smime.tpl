{
	"subject": {{ toJson .Token.email }},
        "sans": {{ toJson .SANs }},
	"keyUsage": ["DigitalSignature"],
	"extkeyUsage": ["EmailProtection"]
}
