abstract class OpenSSL::SSL::Context
  getter freed : Bool = false

  def finalize
    free
  end

  def free
    return if @freed
    @freed = true

    LibSSL.ssl_ctx_free(@handle)
  end
end
