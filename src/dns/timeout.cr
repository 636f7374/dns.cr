struct DNS::TimeOut
  property read : Time::Span
  property write : Time::Span
  property connect : Time::Span

  def initialize(@read : Time::Span = 30_i32.seconds, @write : Time::Span = 30_i32.seconds, @connect : Time::Span = 10_i32.seconds)
  end
end
