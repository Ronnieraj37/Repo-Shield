// Fill the deployed contract address and start block into subgraph.yaml.
//   node set-address.mjs 0xADDRESS 1234567
import { readFileSync, writeFileSync } from "node:fs";

const [address, startBlock] = process.argv.slice(2);
if (!address || !startBlock) {
  console.error("usage: node set-address.mjs <address> <startBlock>");
  process.exit(1);
}

let yaml = readFileSync("subgraph.yaml", "utf8");
yaml = yaml.replace(/address:\s*"0x[0-9a-fA-F]+"/, `address: "${address}"`);
yaml = yaml.replace(/startBlock:\s*\d+/, `startBlock: ${startBlock}`);
writeFileSync("subgraph.yaml", yaml);
console.log(`subgraph.yaml → address ${address}, startBlock ${startBlock}`);
