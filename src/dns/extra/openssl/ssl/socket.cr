class OpenSSL::SSL::Socket
  getter freed : Bool
  getter freeMutex : Mutex

  protected def initialize(io, context : Context, @sync_close : Bool = false)
    @freed = false
    @freeMutex = Mutex.new :unchecked

    @closed = false

    @ssl = LibSSL.ssl_new context
    unless @ssl
      raise OpenSSL::Error.new "SSL_new"
    end

    # Since OpenSSL::SSL::Socket is buffered it makes no
    # sense to wrap a IO::Buffered with buffering activated.

    if io.is_a? IO::Buffered
      io.sync = true
      io.read_buffering = false
    end

    @bio = BIO.new io
    LibSSL.ssl_set_bio @ssl, @bio, @bio
  end

  def ssl_context=(value : Context)
    @sslContext = value
  end

  def ssl_context : Context?
    @sslContext
  end

  private def free_ssl_context : Bool
    ssl_context.try &.free
    @sslContext = nil

    true
  end

  def finalize
    @freeMutex.synchronize do
      return if @freed

      LibSSL.ssl_free @ssl
      free_ssl_context

      @freed = true
    end
  end

  private def __unbuffered_close : Nil
    begin
      loop do
        begin
          ret = LibSSL.ssl_shutdown @ssl
          break if ret == 1                # done bidirectional
          break if ret == 0 && sync_close? # done unidirectional, "this first successful call to SSL_shutdown() is sufficient"
          raise OpenSSL::SSL::Error.new(@ssl, ret, "SSL_shutdown") if ret < 0
        rescue e : OpenSSL::SSL::Error
          case e.error
          when .want_read?, .want_write?
            # Ignore, shutdown did not complete yet
          when .syscall?
            # OpenSSL claimed an underlying syscall failed, but that didn't set any error state,
            # assume we're done

            break
          else
            raise e
          end
        end

        # ret == 0, retry, shutdown is not complete yet
      end
    rescue IO::Error
    ensure
      @bio.io.close if @sync_close
    end
  end

  def close : Nil
    unbuffered_close
  end

  def unbuffered_close : Nil
    @freeMutex.synchronize do
      return if @freed && @closed
      @closed = true
      exception = nil

      begin
        __unbuffered_close
      rescue ex
        exception = ex
      end

      LibSSL.ssl_free @ssl
      free_ssl_context

      @freed = true
      exception.try { |_exception| raise _exception }
    end
  end
end
