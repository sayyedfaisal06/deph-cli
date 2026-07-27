const vscode = require("vscode");

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand("deph.openStudio", () => {
      const terminal = vscode.window.createTerminal({ name: "deph studio" });
      terminal.show();
      // No arguments: deph finds the .deph file and opens the browser itself.
      terminal.sendText("deph studio");
    })
  );
}

module.exports = { activate };
