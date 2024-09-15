const fs = require('fs');
fs.writeFileSync('/tmp/compromised.txt', 'Server has been compromised!');
