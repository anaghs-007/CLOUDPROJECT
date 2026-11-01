// src/expression/parsing_error.ts
var ExpressionParsingError = class extends Error {
	constructor(key, message) {
		super(message);
		this.message = message;
		this.key = key;
	}
};
export { ExpressionParsingError };

//# sourceMappingURL=parsing_error.mjs.map