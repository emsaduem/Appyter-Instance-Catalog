import os
from app.app import app
app.debug=True
app.run(port=os.environ.get('DEBUG_PORT', 8080), host='0.0.0.0', debug=True)
