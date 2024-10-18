const { spawn } = require('child_process');
const path = require('path');

const app = spawn('python', [path.join(__dirname, 'app.py')]);

app.stdout.on('data', (data) => {
  console.log(`stdout: ${data}`);
});

app.stderr.on('data', (data) => {
  console.error(`stderr: ${data}`);
});

app.on('close', (code) => {
  console.log(`child process exited with code ${code}`);
});

