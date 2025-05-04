const { readdirSync, readFileSync, rmSync, writeFileSync } = require("node:fs");
const { precompile } = require("handlebars");
const { join } = require("node:path");

console.log("=== Templates Precompile STARTED ===");

const templatesDirectory = "src/auth/web/templates";
const fileNames = readdirSync(templatesDirectory, {
	recursive: false
}).filter((e) => e.endsWith(".hbs"));

const outFilePath = join(templatesDirectory, "compiled.ts");
console.log("removing old file: ", outFilePath);
rmSync(outFilePath, { force: true });

if (fileNames.length === 0) {
	console.warn("no files found to process, exiting now");
	console.log("=== Templates Precompile ENDED ===");
	return;
}

console.log(`found ${fileNames.length} template files to process`);
const lines = [];
lines.push("// @ts-nocheck");
lines.push('import {TemplateDelegate, template} from "handlebars";');
lines.push("");
for (let i = 0, l = fileNames.length; i < l; i++) {
	const fileName = fileNames[i];
	const propName = fileName.substring(0, fileName.length - 4);
	console.log("processing: ", fileName);
	const rawTemplate = readFileSync(join(templatesDirectory, fileName), {
		encoding: "utf-8"
	});
	const obj = precompile(rawTemplate);
	lines.push(`export const ${propName}:TemplateDelegate = template(${obj.toString()});`);
}

console.log("writing output to file: ", outFilePath);
writeFileSync(outFilePath, lines.join("\n"), {
	encoding: "utf-8"
});

console.log("=== Templates Precompile ENDED ===");
