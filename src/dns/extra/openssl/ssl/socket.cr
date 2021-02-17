class OpenSSL::SSL::Socket
  def skip_finalize=(value : Bool)
    @skipFinalize = value
  end

  def skip_finalize
    @skipFinalize
  end

  def free
    return unless skip_finalize
    LibSSL.ssl_free @ssl
  end

  def finalize
    return if skip_finalize
    LibSSL.ssl_free @ssl
  end
end
