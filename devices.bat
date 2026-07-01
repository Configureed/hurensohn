# Get all devices
GET /api/v1/devices
Headers: X-API-Key: YOUR_API_KEY

# Register device
POST /api/v1/devices
Headers: X-API-Key: YOUR_API_KEY
{
  "name": "My Device",
  "deviceType": "Windows"
}