abstract class OpenSSL::SSL::Context
  getter freed : Bool
  getter freeMutex : Mutex

  protected def initialize(method : LibSSL::SSLMethod)
    @freed = false
    @freeMutex = Mutex.new :unchecked

    @handle = LibSSL.ssl_ctx_new(method)
    raise OpenSSL::Error.new("SSL_CTX_new") if @handle.null?

    set_default_verify_paths

    add_options(OpenSSL::SSL::Options.flags(
      ALL,
      NO_SSL_V2,
      NO_SSL_V3,
      NO_TLS_V1,
      NO_TLS_V1_1,
      NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
      SINGLE_ECDH_USE,
      SINGLE_DH_USE
    ))

    {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.1.0") >= 0 %}
      add_options(OpenSSL::SSL::Options::NO_RENEGOTIATION)
    {% end %}

    add_modes(OpenSSL::SSL::Modes.flags(AUTO_RETRY, RELEASE_BUFFERS))
  end

  def free
    @freeMutex.synchronize do
      return if @freed

      LibSSL.ssl_ctx_free(@handle)
      @freed = true
    end
  end

  def finalize
    free
  end
end
