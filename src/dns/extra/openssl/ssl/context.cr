class OpenSSL::SSL::Context
  def skip_finalize=(value : Bool)
    @skipFinalize = value
  end

  def skip_finalize
    @skipFinalize
  end

  def free
    return unless skip_finalize
    LibSSL.ssl_ctx_free @handle
  end

  def finalize
    return if skip_finalize
    LibSSL.ssl_ctx_free @handle
  end
end
