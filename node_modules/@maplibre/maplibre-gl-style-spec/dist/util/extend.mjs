// src/util/extend.ts
function extendBy(output, ...inputs) {
	for (const input of inputs) for (const k in input) output[k] = input[k];
	return output;
}
export { extendBy };

//# sourceMappingURL=extend.mjs.map