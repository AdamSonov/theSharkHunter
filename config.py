import sys
import warnings

# Custom filter to ignore specific warnings
warnings.filterwarnings(
    "ignore", 
    message=".*Mac address to reach destination not found.*"
)

# Set the default encoding to utf-8
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')



#virusTotal Api_KEY
virusTotal_api_Key = "Put Your virus Total ApiKey here"
