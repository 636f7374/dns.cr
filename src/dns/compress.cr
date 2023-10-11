module DNS::Compress
  def self.decode(protocol_type : ProtocolType, io : IO, buffer : IO::Memory) : String
    pointer_buffer = uninitialized UInt8[1_i32]
    pointer_value = 0_u16
    before_buffer_position = buffer.pos
    value = String.new

    loop do
      io.read_fully slice: pointer_buffer.to_slice
      pointer_slice = pointer_buffer.to_slice
      pointer_value = pointer_slice[0_u8].dup.to_u16
      buffer.write slice: pointer_slice
      break if pointer_value.zero?

      # References: A warm welcome to DNS - https://powerdns.org/hello-dns/basic.md.html
      # In this case, the DNS name of the answer is encoded is 0xc0 0x0c.
      # The c0 part has the two most significant bits set, indicating that the following 6+8 bits are a pointer to somewhere earlier in the message.
      # In this case, this points to position 12 (= 0x0c) within the packet, which is immediately after the DNS header.
      # There we find 'www.ietf.org'.
      # Note: (pointer 6bits + offset 8bits)

      if pointer_value >= 0b11000000
        read_length = io.read slice: pointer_buffer.to_slice
        raise Exception.new "Compress.decode: (Pointer) Failed to read 1 Bytes from IO!" unless 1_i32 == read_length
        pointer_slice = pointer_buffer.to_slice
        pointer_value = (((pointer_value & 0b00000011_u8).to_u16 << 8_u8) | pointer_slice[0_u8])
        pointer_value += 2_i32 if protocol_type.tcp? || protocol_type.tls?
        buffer.write slice: pointer_slice

        before_buffer_position = buffer.pos
        buffer.pos = pointer_value

        64_u8.times do
          buffer.read_fully slice: pointer_buffer.to_slice
          pointer_slice = pointer_buffer.to_slice
          pointer_value = pointer_slice[0_u8].dup.to_u16
          break if pointer_value.zero?

          if pointer_value >= 0b11000000
            read_length = buffer.read_fully slice: pointer_buffer.to_slice
            pointer_slice = pointer_buffer.to_slice
            pointer_value = (((pointer_value & 0b00000011_u8).to_u16 << 8_u8) | pointer_slice[0_u8])
            pointer_value += 2_i32 if protocol_type.tcp? || protocol_type.tls?

            buffer.pos = pointer_value
          else
            fragment = Bytes.new size: pointer_value
            read_length = buffer.read_fully slice: fragment
            value += String.new(fragment[0_u8, read_length])
            value += '.'
          end
        end

        # Restore Position.

        buffer.pos = before_buffer_position
        break
      else
        fragment = Bytes.new size: pointer_value
        read_length = io.read_fully slice: fragment
        buffer.write slice: fragment[0_u8, read_length]

        value += String.new(fragment[0_u8, read_length])
        value += '.'
      end
    end

    value.ends_with?('.') ? value[0_u8, (value.size - 1_u8)] : value
  end

  def self.encode(io : IO, value : String)
    return io.write slice: Bytes[0_u8] if value.empty?

    parts = value.split '.'
    parts.pop if parts.last.empty?

    parts.each do |part|
      io.write_bytes part.size.to_u8
      io << part
    end

    io.write slice: Bytes[0_u8]
  end
end
