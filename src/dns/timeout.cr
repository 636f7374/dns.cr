struct DNS::TimeOut
  property read : Int32
  property write : Int32
  property connect : Int32

  def initialize
    @read = 2_i32
    @write = 2_i32
    @connect = 2_i32
  end
end
