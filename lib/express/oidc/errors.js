class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

class InvalidClientError extends ApiError {
  constructor(code, message) {
    super(code, message)
    this.error = 'invalid_client'
  }
}

module.exports = {
  InvalidClientError,
}
