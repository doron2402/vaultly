import readline from 'node:readline';

// Prompt without echoing the typed characters (for passwords).
export function promptHidden(question) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      // Piped input (scripts, tests): read one line.
      let data = '';
      process.stdin.setEncoding('utf8');
      const onData = (chunk) => {
        data += chunk;
        const nl = data.indexOf('\n');
        if (nl !== -1) {
          process.stdin.removeListener('data', onData);
          process.stdin.pause();
          resolve(data.slice(0, nl).replace(/\r$/, ''));
        }
      };
      process.stdin.on('data', onData);
      process.stdin.on('end', () => resolve(data.replace(/\r?\n?$/, '')));
      process.stdin.on('error', reject);
      return;
    }

    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    let muted = false;
    const origWrite = rl._writeToOutput.bind(rl);
    rl._writeToOutput = (str) => {
      if (!muted) origWrite(str);
    };
    rl.on('SIGINT', () => {
      process.stderr.write('\n');
      process.exit(130);
    });
    rl.question(question, (answer) => {
      rl.close();
      process.stderr.write('\n');
      resolve(answer);
    });
    muted = true; // everything after the question itself stays hidden
  });
}

export async function getMasterPassword({ confirm = false, promptText = 'Master password: ' } = {}) {
  if (process.env.PASSLY_PASSWORD !== undefined) return process.env.PASSLY_PASSWORD;
  const password = await promptHidden(promptText);
  if (!password) throw new Error('password cannot be empty');
  if (confirm) {
    const again = await promptHidden('Confirm password: ');
    if (again !== password) throw new Error('passwords do not match');
  }
  return password;
}
