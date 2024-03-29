module DNS::Serialized
  struct TimeOut
    include YAML::Serializable

    property read : Int32
    property write : Int32
    property connect : Int32

    def initialize
      @read = 2_i32
      @write = 2_i32
      @connect = 2_i32
    end

    def unwrap : DNS::TimeOut
      timeout = DNS::TimeOut.new

      timeout.read = read
      timeout.write = write
      timeout.connect = connect

      timeout
    end
  end
end
