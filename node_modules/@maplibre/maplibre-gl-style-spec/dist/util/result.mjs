// src/util/result.ts
function success(value) {
	return {
		result: "success",
		value
	};
}
function error(value) {
	return {
		result: "error",
		value
	};
}
export { error, success };

//# sourceMappingURL=result.mjs.map