#!/bin/bash

# Initialize CouchDB database for shared notes
# This script creates the necessary design documents and views for shares functionality

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Default values if not set in .env
COUCHDB_URL=${COUCHDB_URL:-"http://localhost:5984"}
COUCHDB_USERNAME=${COUCHDB_USER:-"admin"}
COUCHDB_PASSWORD=${COUCHDB_PASSWORD:-"password"}
DB_NAME=${DB_NAME:-"notes"}

echo "Initializing CouchDB database for shared notes..."
echo "Database: $DB_NAME"
echo "URL: $COUCHDB_URL"

# Create design document for shares
echo "Creating shares design document..."

SHARES_DESIGN='{
  "_id": "_design/shares",
  "views": {
    "by_user": {
      "map": "function(doc) { if(doc.type === \"share\" && doc.owner_id) emit(doc.owner_id, doc); }"
    },
    "by_share_id": {
      "map": "function(doc) { if(doc.type === \"share\" && doc.share_id) emit(doc.share_id, doc); }"
    },
    "by_note_id": {
      "map": "function(doc) { if(doc.type === \"share\" && doc.note_id) emit(doc.note_id, doc); }"
    },
    "public_shares": {
      "map": "function(doc) { if(doc.type === \"share\" && doc.share_type === \"public\") emit(doc.share_id, doc); }"
    },
    "expired_shares": {
      "map": "function(doc) { if(doc.type === \"share\" && doc.expires_at && new Date(doc.expires_at) < new Date()) emit(doc.share_id, doc); }"
    }
  }
}'

# Check if design document already exists and get its revision
echo "Checking if design document already exists..."
EXISTING_DOC=$(curl -s -X GET \
  "$COUCHDB_URL/$DB_NAME/_design/shares" \
  -u "$COUCHDB_USERNAME:$COUCHDB_PASSWORD")

if echo "$EXISTING_DOC" | grep -q '"_rev"'; then
    # Document exists, get the revision
    REV=$(echo "$EXISTING_DOC" | grep -o '"_rev":"[^"]*"' | cut -d'"' -f4)
    echo "Design document exists with revision: $REV"
    # Create design document with revision
    SHARES_DESIGN="{
  \"_id\": \"_design/shares\",
  \"_rev\": \"$REV\",
  \"views\": {
    \"by_user\": {
      \"map\": \"function(doc) { if(doc.type === \\\"share\\\" && doc.owner_id) emit(doc.owner_id, doc); }\"
    },
    \"by_share_id\": {
      \"map\": \"function(doc) { if(doc.type === \\\"share\\\" && doc.share_id) emit(doc.share_id, doc); }\"
    },
    \"by_note_id\": {
      \"map\": \"function(doc) { if(doc.type === \\\"share\\\" && doc.note_id) emit(doc.note_id, doc); }\"
    },
    \"public_shares\": {
      \"map\": \"function(doc) { if(doc.type === \\\"share\\\" && doc.share_type === \\\"public\\\") emit(doc.share_id, doc); }\"
    },
    \"expired_shares\": {
      \"map\": \"function(doc) { if(doc.type === \\\"share\\\" && doc.expires_at && new Date(doc.expires_at) < new Date()) emit(doc.share_id, doc); }\"
    }
  }
}"
    echo "Updating existing design document..."
else
    echo "Design document doesn't exist, creating new one..."
fi

# Upload the design document
RESPONSE=$(curl -s -X PUT \
  "$COUCHDB_URL/$DB_NAME/_design/shares" \
  -H "Content-Type: application/json" \
  -u "$COUCHDB_USERNAME:$COUCHDB_PASSWORD" \
  -d "$SHARES_DESIGN")

if echo "$RESPONSE" | grep -q '"ok":true'; then
    echo "✅ Shares design document created/updated successfully"
elif echo "$RESPONSE" | grep -q '"error":"conflict"'; then
    echo "⚠️  Design document already exists with same content"
else
    echo "❌ Failed to create/update shares design document"
    echo "Response: $RESPONSE"
    exit 1
fi

# Test the views
echo "Testing shares views..."

# Test by_user view
curl -s -X GET \
  "$COUCHDB_URL/$DB_NAME/_design/shares/_view/by_user?limit=1" \
  -u "$COUCHDB_USERNAME:$COUCHDB_PASSWORD" > /dev/null

if [ $? -eq 0 ]; then
    echo "✅ by_user view working"
else
    echo "❌ by_user view failed"
fi

# Test by_share_id view
curl -s -X GET \
  "$COUCHDB_URL/$DB_NAME/_design/shares/_view/by_share_id?limit=1" \
  -u "$COUCHDB_USERNAME:$COUCHDB_PASSWORD" > /dev/null

if [ $? -eq 0 ]; then
    echo "✅ by_share_id view working"
else
    echo "❌ by_share_id view failed"
fi

# Test by_note_id view
curl -s -X GET \
  "$COUCHDB_URL/$DB_NAME/_design/shares/_view/by_note_id?limit=1" \
  -u "$COUCHDB_USERNAME:$COUCHDB_PASSWORD" > /dev/null

if [ $? -eq 0 ]; then
    echo "✅ by_note_id view working"
else
    echo "❌ by_note_id view failed"
fi

# Test public_shares view
curl -s -X GET \
  "$COUCHDB_URL/$DB_NAME/_design/shares/_view/public_shares?limit=1" \
  -u "$COUCHDB_USERNAME:$COUCHDB_PASSWORD" > /dev/null

if [ $? -eq 0 ]; then
    echo "✅ public_shares view working"
else
    echo "❌ public_shares view failed"
fi

# Test expired_shares view
curl -s -X GET \
  "$COUCHDB_URL/$DB_NAME/_design/shares/_view/expired_shares?limit=1" \
  -u "$COUCHDB_USERNAME:$COUCHDB_PASSWORD" > /dev/null

if [ $? -eq 0 ]; then
    echo "✅ expired_shares view working"
else
    echo "❌ expired_shares view failed"
fi

echo ""
echo "🎉 Database initialization for shared notes completed!"
echo ""
echo "Available views:"
echo "- by_user: Find shares by owner"
echo "- by_share_id: Find share by share ID"  
echo "- by_note_id: Find shares by note ID"
echo "- public_shares: Find all public shares"
echo "- expired_shares: Find expired shares"
echo ""
echo "You can now use the shared notes functionality in your API."
