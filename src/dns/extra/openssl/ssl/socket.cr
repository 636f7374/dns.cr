class OpenSSL::SSL::Socket
  getter freed : Bool = false

  def ssl_context=(value : Context)
    @sslContext = value
  end

  def ssl_context : Context?
    @sslContext
  end

  def finalize
    free
  end

  def free
    return if @freed
    @freed = true

    LibSSL.ssl_free @ssl
  end
end

class OpenSSL::SSL::SuperSocket < IO
  getter socket : OpenSSL::SSL::Socket
  getter sslContext : Context?
  getter closeAfterFinalize : Bool
  getter freed : Atomic(Int8)
  getter readMutex : Mutex
  getter writeMutex : Mutex
  getter mutex : Mutex

  def initialize(@socket : OpenSSL::SSL::Socket, @sslContext : Context?, @closeAfterFinalize : Bool)
    @freed = Atomic(Int8).new value: -1_i8
    @readMutex = Mutex.new :unchecked
    @writeMutex = Mutex.new :unchecked
    @mutex = Mutex.new :unchecked
  end

  def read_timeout=(value : Int | Time::Span | Nil)
    _socket = @socket
    _socket.read_timeout = value if _socket.responds_to? :read_timeout=
  end

  def read_timeout
    @socket.read_timeout
  end

  def write_timeout=(value : Int | Time::Span | Nil)
    _socket = @socket
    _socket.write_timeout = value if _socket.responds_to? :write_timeout=
  end

  def write_timeout
    @socket.write_timeout
  end

  def sync=(value : Bool)
    _socket = @socket
    _socket.sync = value if _socket.responds_to? :sync=
  end

  def read_buffering=(value : Bool)
    _socket = @socket
    _socket.read_buffering = value if _socket.responds_to? :read_buffering=
  end

  def local_address
    @socket.local_address
  end

  def remote_address
    @socket.remote_address
  end

  def read(slice : Bytes) : Int32
    @readMutex.synchronize do
      raise Exception.new "OpenSSL::SSL::SuperSocket.read: socket, sslContext freed!" if @freed.get.zero?
      return @socket.read slice: slice
    end
  end

  def write(slice : Bytes) : Nil
    @writeMutex.synchronize do
      raise Exception.new "OpenSSL::SSL::SuperSocket.write: socket, sslContext freed!" if @freed.get.zero?
      return @socket.write slice: slice
    end
  end

  def close : Bool
    exception = nil

    @mutex.synchronize do
      return true if @freed.get.zero?

      begin
        @socket.close
      rescue ex
        exception = ex
      end

      @freed.set value: 0_i8
      readMutex.lock
      writeMutex.lock

      if @closeAfterFinalize
        @socket.free
        @sslContext.try &.free
      end

      readMutex.unlock
      writeMutex.unlock
    end

    exception.try { |_exception| raise _exception }
    true
  end
end
