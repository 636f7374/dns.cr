struct DNS::Packet
  enum ARType : UInt16
    Ask   = 0b0000000000000000_u16
    Reply = 0b1000000000000000_u16
  end

  enum OperationCodeFlag : UInt16
    StandardQuery = 0b0000000000000000_u16
    InverseQuery  = 0b0000100000000000_u16
    Status        = 0b0001000000000000_u16
    Reserved      = 0b0001100000000000_u16
    Notify        = 0b0010000000000000_u16
    Update        = 0b0010100000000000_u16
  end

  enum AuthoritativeAnswerFlag : UInt16
    True  = 0b0000010000000000_u16
    False = 0b0000000000000000_u16
  end

  enum TruncatedFlag : UInt16
    True  = 0b0000001000000000_u16
    False = 0b0000000000000000_u16
  end

  enum RecursionDesiredFlag : UInt16
    True  = 0b0000000100000000_u16
    False = 0b0000000000000000_u16
  end

  enum RecursionAvailableFlag : UInt16
    True  = 0b0000000010000000_u16
    False = 0b0000000000000000_u16
  end

  enum AuthenticatedDataFlag : UInt16
    True  = 0b0000000000100000_u16
    False = 0b0000000000000000_u16
  end

  enum CheckingDisabledFlag : UInt16
    True  = 0b0000000000010000_u16
    False = 0b0000000000000000_u16
  end

  enum ErrorFlag : UInt16
    NoError        = 0b0000000000000000_u16
    FormatError    = 0b0000000000000001_u16
    ServerFailure  = 0b0000000000000010_u16
    NameError      = 0b0000000000000011_u16
    NotImplemented = 0b0000000000000100_u16
    Refused        = 0b0000000000000101_u16
    YXDomain       = 0b0000000000000110_u16
    YXRRSet        = 0b0000000000000111_u16
    NXRRSet        = 0b0000000000001000_u16
    NotAuth        = 0b0000000000001001_u16
    NotZone        = 0b0000000000001010_u16
  end

  enum RecordFlag : UInt16
    ANY        =   255_u16
    AXFR       =   252_u16
    IXFR       =   251_u16
    OPT        =    41_u16
    A          =     1_u16
    AAAA       =    28_u16
    AFSDB      =    18_u16
    APL        =    42_u16
    CAA        =   257_u16
    CDNSKEY    =    60_u16
    CDS        =    59_u16
    CERT       =    37_u16
    CNAME      =     5_u16
    DHCID      =    49_u16
    DLV        = 32769_u16
    DNAME      =    39_u16
    DNSKEY     =    48_u16
    DS         =    43_u16
    HIP        =    55_u16
    IPSECKEY   =    25_u16
    KX         =    36_u16
    LOC        =    29_u16
    MX         =    15_u16
    NAPTR      =    35_u16
    NS         =     2_u16
    NSEC       =    47_u16
    NSEC3      =    50_u16
    NSEC3PARAM =    51_u16
    OPENPGPKEY =    61_u16
    PTR        =    12_u16
    RRSIG      =    46_u16
    RP         =    17_u16
    SIG        =    24_u16
    SOA        =     6_u16
    SRV        =    33_u16
    SSHFP      =    44_u16
    TA         = 32768_u16
    TKEY       =   249_u16
    TLSA       =    52_u16
    TSIG       =   250_u16
    TXT        =    16_u16
    URI        =   256_u16
    MD         =     3_u16
    MF         =     4_u16
    MAILA      =   254_u16
    MB         =     7_u16
    MG         =     8_u16
    MR         =     9_u16
    MINFO      =    14_u16
    MAILB      =   253_u16
    WKS        =    11_u16
    NB         =    32_u16
    NBSTAT     =    33_u16
    NULL       =    10_u16
    A6         =    38_u16
    NXT        =    30_u16
    KEY        =    25_u16
    HINFO      =    13_u16
    X25        =    19_u16
    ISDN       =    20_u16
    RT         =    21_u16
    NSAP       =    22_u16
    NSAP_PTR   =    23_u16
    PX         =    26_u16
    EID        =    31_u16
    NIMLOC     =    32_u16
    ATMA       =    34_u16
    SINK       =    40_u16
    GPOS       =    27_u16
    UINFO      =   100_u16
    UID        =   101_u16
    GID        =   102_u16
    UNSPEC     =   103_u16
    SPF        =    99_u16

    # (ANY - OPT) - __Pseudo Record Types
    # (__A - URI) - __Active Record Types
    # (_MD - SPF) - Obsolete Record Types

  end

  enum ClassFlag : UInt16
    Reserved        =     0_u16
    Internet        =     1_u16
    Unassigned      =     2_u16
    Chaosnet        =     3_u16
    Hesiod          =     4_u16
    QClassNone      =   254_u16
    QClassAny       =   255_u16
    AnotherReserved = 65535_u16

    # (0x0000/00000) - (0x0000/00000) Reserved: RFC 6895
    # (0x0001/00001) - (0x0001/00001) Internet: RFC 1035
    # (0x0003/00003) - (0x0003/00003) Chaosnet: RFC 2929 | D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981.
    # (0x0004/00004) - (0x0004/00004) Hesiod: Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987.
    # (0x0005/00005) - (0x00FD/00253) Unassigned
    # (0x00FE/00254) - (0x00FE/00254) QClassNone: RFC 2136
    # (0x00FF/00255) - (0x00FF/00255) QClassAny: RFC 1035
    # (0x0100/00256) - (0xFEFF/65279) Unassigned
    # (0xFF00/65280) - (0xFFFE/65534) Reserved for Private Use: RFC 6895
    # (0xFFFF/65535) - (0xFFFF/65535) AnotherReserved: RFC 6895

  end

  property arType : ARType
  property protocolType : ProtocolType
  property! transmissionId : UInt16
  property! operationCodeType : OperationCodeFlag
  property! authoritativeAnswerType : AuthoritativeAnswerFlag
  property! truncatedType : TruncatedFlag
  property! recursionDesiredType : RecursionDesiredFlag
  property! recursionAvailableType : RecursionAvailableFlag
  property! authenticatedDataType : AuthenticatedDataFlag
  property! checkingDisabledType : CheckingDisabledFlag
  property! errorType : ErrorFlag
  property! questionCount : UInt16
  property! answerCount : UInt16
  property! authorityCount : UInt16
  property! additionalCount : UInt16
  property queries : Set(Sections::Question)
  property answers : Set(Records)
  property authority : Set(Records)
  property additional : Set(Records)
  property! buffer : IO::Memory

  def initialize(@arType : ARType, @protocolType : ProtocolType)
    @queries = Set(Sections::Question).new
    @answers = Set(Records).new
    @authority = Set(Records).new
    @additional = Set(Records).new
  end

  def check_error(ar_type : ARType, transmission_id : UInt16) : Bool
    raise Exception.new "Packet.check_error: The packet.arType does not match the expected arType!" if ar_type != arType
    raise Exception.new "Packet.check_error: The packet.transmissionId does not match the expected transmissionId!" if transmission_id != transmissionId
    raise Exception.new "Packet.check_error: The packet.errorType is not Packet::ErrorFlag::NoError!" unless errorType.no_error?

    true
  end

  @[Deprecated]
  def self.create_getaddrinfo_ask(protocol_type : ProtocolType, name : String, record_type : RecordFlag, class_type : ClassFlag = ClassFlag::Internet)
    create_query_packet protocol_type: protocol_type, name: name, record_type: record_type, class_type: class_type
  end

  def self.create_query_packet(protocol_type : ProtocolType, name : String, record_type : RecordFlag, class_type : ClassFlag = ClassFlag::Internet)
    packet = new arType: ARType::Ask, protocolType: protocol_type

    {% begin %}
      case record_type
        {% for available_type in AvailableRecordFlags %}
      when .{{available_type.downcase.id}}?
        packet.queries << Sections::Question.new recordType: RecordFlag::{{available_type.upcase.id}}, name: name, classType: class_type
        {% end %}
      end
    {% end %}

    packet.operationCodeType = OperationCodeFlag::StandardQuery
    packet.errorType = ErrorFlag::NoError
    packet.authoritativeAnswerType = AuthoritativeAnswerFlag::False
    packet.truncatedType = TruncatedFlag::False
    packet.recursionDesiredType = RecursionDesiredFlag::True
    packet.recursionAvailableType = RecursionAvailableFlag::False
    packet.authenticatedDataType = AuthenticatedDataFlag::False
    packet.checkingDisabledType = CheckingDisabledFlag::False

    packet
  end

  def self.from_slice(protocol_type : ProtocolType, slice : Bytes, buffer : IO::Memory = IO::Memory.new, options : Options = Options.new) : Packet
    slice_io = IO::Memory.new slice
    from_io protocol_type: protocol_type, io: slice_io, buffer: buffer, options: options
  end

  def self.from_io(protocol_type : ProtocolType, io : IO, buffer : IO::Memory = IO::Memory.new, options : Options = Options.new) : Packet
    case protocol_type
    when .udp?
    when ProtocolType::TCP, ProtocolType::TLS
      packet_size = read_packet_size! protocol_type: protocol_type, io: io
    end

    transmission_id = read_transmission_id! io: io
    flags = read_flags! io: io

    packet = decode_integer_flags! protocol_type: protocol_type, flags: flags
    packet = update_record_count! io: io, packet: packet
    check_threshold! packet_size: packet_size, packet: packet, options: options

    set_buffer buffer: buffer, packet_size: packet_size, transmission_id: transmission_id, flags: flags, packet: packet

    packet.questionCount.times { packet.queries << Sections::Question.from_io protocol_type: protocol_type, io: io, buffer: buffer }
    packet.answerCount.times { packet.answers << Sections::Answer.from_io protocol_type: protocol_type, io: io, buffer: buffer }
    packet.authorityCount.times { packet.authority << Sections::Authority.from_io protocol_type: protocol_type, io: io, buffer: buffer }
    packet.additionalCount.times { packet.additional << Sections::Additional.from_io protocol_type: protocol_type, io: io, buffer: buffer }
    packet.transmissionId = transmission_id
    packet.buffer = buffer

    packet
  end

  def to_io(io : IO::Memory)
    case arType
    in .ask?
      write_ask io: io
    in .reply?
      raise Exception.new "Unfortunately, the ARType::Reply type is currently not supported Packet.to_io."
    end

    io
  end

  def to_slice : Bytes
    ask_memory = IO::Memory.new
    to_io ask_memory

    case protocolType
    when .udp?
    when ProtocolType::TCP, ProtocolType::TLS
      ask_slice = ask_memory.to_slice.dup
      ask_slice_size = ask_slice.size.to_u16

      ask_memory.rewind
      ask_memory.clear

      ask_memory.write_bytes ask_slice_size, IO::ByteFormat::BigEndian
      ask_memory.write ask_slice
    else
      raise Exception.new String.build { |io| io << "Unfortunately, protocolType (" << protocolType << ") is not supported!" }
    end

    ask_memory.to_slice
  end

  # * Ask References:
  #   * DNS QUERY MESSAGE FORMAT: http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/160-protocols-dns-query.html
  #   * Protocol and Format: http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html
  #   * How to convert a string or integer to binary in Ruby?: https://stackoverflow.com/questions/2339695/how-to-convert-a-string-or-integer-to-binary-in-ruby
  #   * Numbers: http://www.oualline.com/practical.programmer/numbers.html
  #   * DNS Query Code in C with linux sockets: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

  private def write_ask(io : IO::Memory)
    # * Write transmissionId (2 Bytes)

    io.write_bytes transmissionId, IO::ByteFormat::BigEndian

    # * Control field contains: QR | OpCode | AA | TC | RD | RA | Z | AD | CD | RCODE

    flags = 0b0000000000000000_u16

    # * QR : 1 bit, request (0) or response (1)
    #   * Request not required, set to 1 Zero

    flags = flags | arType.value

    # * OpCode : 4 bits, request type
    #   * |_ QUERY_ Standard request
    #   * |_ IQUERY Inverse request (obsoleted by RFC3425)
    #   * |_ STATUS Server status query
    #   * |_ NOTIFY Database update notification (RFC1996)
    #   * |_ UPDATE Dynamic database update (RFC2136)

    flags = flags | operationCodeType.value

    # * AA Authoritative Answer : 1 bit, reply from authoritative (1) or from cache (0)
    #   * Request not required, set to 1 Zero

    flags = flags | authoritativeAnswerType.value

    # * TC Truncated : 1 bit, response too large for UDP (1).

    flags = flags | truncatedType.value

    # * RD Recursion Desired: 1bit, ask for recursive (1) or iterative (0) response

    flags = flags | recursionDesiredType.value

    # * RA Recursion Available : 1bit, server manages recursive (1) or not (0)
    #   * Request not required, set to 1 Zero

    flags = flags | recursionAvailableType.value

    # * 1 bit Zeros, reserved for extensions
    #   * Request not required, set to 1 Zero

    flags = flags | 0b0000000000000000_u16

    # * 1 bit AD Authenticated data, used by DNSSEC

    flags = flags | authenticatedDataType.value

    # * 1 bit CD Checking Disabled, used by DNSSEC
    #   * Request not required, set to 1 Zero

    flags = flags | checkingDisabledType.value

    # * 4 bits Rcode, Error Codes : NOERROR, SERVFAIL, NXDOMAIN (no such domain), REFUSED...
    #   * Request not required, set to 4 Zero

    flags = flags | errorType.value

    # * Write flags (2 Bytes)

    io.write_bytes flags, IO::ByteFormat::BigEndian

    # * ... count fields give the number of entry in each following sections:
    #   * Question count (2 Bytes)

    io.write_bytes queries.size.to_u16, IO::ByteFormat::BigEndian

    #   * Answer count (2 Bytes)

    io.write_bytes 0_u16, IO::ByteFormat::BigEndian

    #   * Authority count (2 Bytes)

    io.write_bytes 0_u16, IO::ByteFormat::BigEndian

    #   * Additional count (2 Bytes)

    io.write_bytes 0_u16, IO::ByteFormat::BigEndian

    # * Question count equals to 1 in general, but could be 0 or > 1 in very special cases

    queries.each &.to_io io: io
  end

  {% for record_type in ["a", "aaaa"] %}
  def select_answers_{{record_type.id}}_records!(name : String, options : Options = Options.new) : Array(Records::{{record_type.upcase.id}})
    raise Exception.new String.build {|io| io << "Packet.select_answers_" << {{record_type.id.stringify}} << "_records!: Unfortunately, answers is empty!" } if answers.empty?

    _maximum_depth = options.packet.maximumDepthOfCanonicalName.dup
    _maximum_depth += 1_i32

    while !(_maximum_depth -= 1_i32).zero?
      answer = answers.find { |answer| name == answer.name }
      name = answer.canonicalName if answer.is_a? Records::CNAME

      if answer.is_a? Records::{{record_type.upcase.id}}
        selected = answers.select { |answer| (name == answer.name) && answer.is_a?(Records::{{record_type.upcase.id}}) }

        temporary = Set(Records::{{record_type.upcase.id}}).new
        selected.each { |item| temporary << item if item.is_a? Records::{{record_type.upcase.id}} }

        return temporary.to_a
      end
    end

    message = String.build do |io| 
      io << "Packet.select_answers_" << {{record_type.id.stringify}} << "_records!: " << "After (" << options.packet.maximumDepthOfCanonicalName << ") attempts, no any " << {{record_type.upcase.id.stringify}} << " record was found!"
    end

    raise Exception.new message
  end
  {% end %}

  def select_answers_ip_records!(name : String, options : Options = Options.new) : Array(Records)
    raise Exception.new String.build { |io| io << "Packet.select_answers_ip_records!: Unfortunately, answers is empty!" } if answers.empty?

    _maximum_depth = options.packet.maximumDepthOfCanonicalName.dup
    _maximum_depth += 1_i32

    while !(_maximum_depth -= 1_i32).zero?
      answer = answers.find { |answer| name == answer.name }
      name = answer.canonicalName if answer.is_a? Records::CNAME

      if answer.is_a?(Records::A) || answer.is_a?(Records::AAAA)
        return answers.select { |answer| (name == answer.name) && (answer.is_a?(Records::A) || answer.is_a?(Records::AAAA)) }
      end
    end

    message = String.build { |io| io << "Packet.select_answers_ip_records!: " << "After (" << options.packet.maximumDepthOfCanonicalName << ") attempts, no A or AAAA record was found!" }
    raise Exception.new message
  end

  private def self.read_packet_size!(protocol_type : ProtocolType, io : IO) : UInt16?
    begin
      io.read_bytes UInt16, IO::ByteFormat::BigEndian
    rescue ex
      raise Exception.new String.build { |io| io << "Packet.from_io: The protocol type is (" << protocol_type.to_s << "), so 2 Bytes packetLength needs to be read, and reading from IO fails!" }
    end
  end

  private def self.read_transmission_id!(io : IO) : UInt16
    begin
      io.read_bytes UInt16, IO::ByteFormat::BigEndian
    rescue ex
      raise Exception.new "Packet.from_io: 2 Bytes transmissionId needs to be read, and reading from IO fails!"
    end
  end

  private def self.read_flags!(io : IO) : UInt16
    begin
      io.read_bytes UInt16, IO::ByteFormat::BigEndian
    rescue ex
      raise Exception.new "Packet.from_io: 2 Bytes flags needs to be read, and reading from IO fails!"
    end
  end

  private def self.decode_integer_flags!(protocol_type : ProtocolType, flags : UInt16) : Packet
    ar_type = ARType.new flags & ARType::Reply.value
    operation_code_flag = OperationCodeFlag.new (flags >> 11_i32) & 0x0f_u16
    authoritative_answer_flag = AuthoritativeAnswerFlag.new flags & AuthoritativeAnswerFlag::True.value
    truncated_flag = TruncatedFlag.new flags & TruncatedFlag::True.value
    recursion_desired_flag = RecursionDesiredFlag.new flags & RecursionDesiredFlag::True.value
    recursion_available_flag = RecursionAvailableFlag.new flags & RecursionAvailableFlag::True.value
    authenticated_data_flag = AuthenticatedDataFlag.new flags & AuthenticatedDataFlag::True.value
    checking_disabled_flag = CheckingDisabledFlag.new flags & CheckingDisabledFlag::True.value
    error_flag = ErrorFlag.new flags & 0x0f_u16

    packet = new arType: ar_type, protocolType: protocol_type
    packet.operationCodeType = operation_code_flag
    packet.authoritativeAnswerType = authoritative_answer_flag
    packet.truncatedType = truncated_flag
    packet.recursionDesiredType = recursion_desired_flag
    packet.recursionAvailableType = recursion_available_flag
    packet.authenticatedDataType = authenticated_data_flag
    packet.checkingDisabledType = checking_disabled_flag
    packet.errorType = error_flag

    packet
  end

  private def self.update_record_count!(io : IO, packet : Packet) : Packet
    packet.questionCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    packet.answerCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    packet.authorityCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    packet.additionalCount = io.read_bytes UInt16, IO::ByteFormat::BigEndian

    packet
  end

  private def self.set_buffer(buffer : IO::Memory, packet_size : UInt16?, transmission_id : UInt16, flags : UInt16, packet : Packet)
    buffer.write_bytes packet_size, IO::ByteFormat::BigEndian if packet_size
    buffer.write_bytes transmission_id, IO::ByteFormat::BigEndian
    buffer.write_bytes flags, IO::ByteFormat::BigEndian
    buffer.write_bytes packet.questionCount, IO::ByteFormat::BigEndian
    buffer.write_bytes packet.answerCount, IO::ByteFormat::BigEndian
    buffer.write_bytes packet.authorityCount, IO::ByteFormat::BigEndian
    buffer.write_bytes packet.additionalCount, IO::ByteFormat::BigEndian
  end

  private def self.check_threshold!(packet_size : UInt16?, packet : Packet, options : Options)
    raise Exception.new String.build { |io| io << "Packet.check_threshold!: Packet size (" << packet_size << ") is greater than Options.packet.maximumSizeOfPacket (" << options.packet.maximumSizeOfPacket << ")." } if packet_size && packet_size > options.packet.maximumSizeOfPacket
    raise Exception.new String.build { |io| io << "Packet.check_threshold!: Packet.questionCount (" << packet.questionCount << ") is greater than Options.packet.maximumCountOfQuestion (" << options.packet.maximumCountOfQuestion << ")." } if packet.questionCount > options.packet.maximumCountOfQuestion
    raise Exception.new String.build { |io| io << "Packet.check_threshold!: Packet.answerCount (" << packet.answerCount << ") is greater than Options.packet.maximumCountOfAnswer (" << options.packet.maximumCountOfAnswer << ")." } if packet.answerCount > options.packet.maximumCountOfAnswer
    raise Exception.new String.build { |io| io << "Packet.check_threshold!: Packet.authorityCount (" << packet.authorityCount << ") is greater than Options.packet.maximumCountOfAuthority (" << options.packet.maximumCountOfAuthority << ")." } if packet.authorityCount > options.packet.maximumCountOfAuthority
    raise Exception.new String.build { |io| io << "Packet.check_threshold!: Packet.additionalCount (" << packet.additionalCount << ") is greater than Options.packet.maximumCountOfAdditional (" << options.packet.maximumCountOfAdditional << ")." } if packet.additionalCount > options.packet.maximumCountOfAdditional
  end
end

require "./sections/*"
