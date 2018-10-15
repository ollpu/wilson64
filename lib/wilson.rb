##
# Wilson is a pure ruby x86 assembler. No, really. Worst Idea Evar.
# Forked from: https://github.com/seattlerb/wilson/
#
# Refactored by @ollpu to run on modern Ruby, x86-64 (Linux only).
#
# Why "wilson"? I wanted to name it "metal", but there is an existing
# project with that name... So I'm naming it after Wilson Bilkovich, who
# is about as metal as you can get (and it is easier to spell than
# "bilkovich", even tho that sounds more metal).
#
# Wilson is a port (and extension) of the smalltalk x86 assembler by
# Michael Lucas-Smith. I came across it when he presented it at
# Smalltalk SuperPowers at OOPSLA 2008.

require 'fiddle'
require 'fiddle/import'
require 'set'

module LibC
  extend Fiddle::Importer
  dlload "libc.so.6"
  extern "void* mmap(void*, size_t, int, int, int, ptrdiff_t)"
  extern "void* memcpy(void*, const void*, size_t)"
  extern "void* memset(void*, int, size_t)"
  def self.mmap_rwx length
    LibC.mmap(0, length, 0x7, 0x22, -1, 0)
  end
end

class Object
  def subclass_responsibility; raise "subclass responsibility" end
  def no!; false end

  alias :address?          :no!
  alias :future_label?     :no!
  alias :immediate?        :no!
  alias :immediate_value?  :no!
  alias :label?            :no!
  alias :offset?           :no!
  alias :operand?          :no!
  alias :register?         :no!
  alias :special_register? :no!
end


module Wilson
  VERSION = '1.1.2'

  ##
  # Assembler parses the instruction list and creates Command
  # objects for it

  class Assembler
    attr_accessor :commands
    attr_accessor :commands_by_mnemonic

    def self.instruction_list
      File.read(__FILE__).split("__END__").last
    end

    @@default = nil

    def self.default
      @@default ||= self.new.parse
    end

    def self.default= o
      @@default = o
    end

    def self.commands
      self.default.commands
    end
    
    def self.commands_by_mnemonic
      self.default.commands_by_mnemonic
    end

    def self.parse
      self.default
    end

    def initialize
      self.commands = []
      self.commands_by_mnemonic = {}
    end

    def expand_parameters command
      gen_commands = [command]
      command.parameters.each_with_index do |parameter, index|
        if String === parameter && parameter.start_with?('rm')
          bits = parameter[2..-1].to_i
          new_command = command.dup
          gen_commands << new_command
          command.parameters[index]     = Register.new bits
          new_command.parameters[index] = Address.new false, bits
          break
        end
      end
      gen_commands
    end

    CONDITIONALS = {
      'O'   =>  0, 'NO' =>  1, 'B'  =>  2, 'C'   =>  2, 'NAE' =>  2,
      'AE'  =>  3, 'NB' =>  3, 'NC' =>  3, 'E'   =>  4, 'Z'   =>  4,
      'NE'  =>  5, 'NZ' =>  5, 'BE' =>  6, 'NA'  =>  6, 'A'   =>  7,
      'NBE' =>  7, 'S'  =>  8, 'NS' =>  9, 'P'   => 10, 'PE'  => 10,
      'NP'  => 11, 'PO' => 11, 'L'  => 12, 'NGE' => 12, 'GE'  => 13,
      'NL'  => 13, 'LE' => 14, 'NG' => 14, 'G'   => 15, 'NLE' => 15,
    }
    
    def expand_conditional_commands prototype
      prototype.mnemonic = prototype.mnemonic[0..-3]
      gen_commands = []

      CONDITIONALS.each do |conditional, value|
        command = prototype.dup
        command.mnemonic += conditional
        gen_commands << command

        command.opcodes.each_with_index do |op, index|
          command.opcodes[index] = (op.hex+value).to_s(16) if op.end_with? '+c'
        end
      end
      gen_commands
    end
    
    def to_parameter parameter
      @simple_parameters ||= begin
        # Cached for performance, values must be such that they aren't mutated
        {
          'reg_al'   => Register.on_id_bits(nil, 0, 8),
          'reg_ax'   => Register.on_id_bits(nil, 0, 16),
          'reg_eax'  => Register.on_id_bits(nil, 0, 32),
          'reg_rax'  => Register.on_id_bits(nil, 0, 64),
          'reg_cl'   => Register.on_id_bits(nil, 1, 8),
          'reg_cx'   => Register.on_id_bits(nil, 1, 16),
          'reg_ecx'  => Register.on_id_bits(nil, 1, 32),
          'reg_rcx'  => Register.on_id_bits(nil, 1, 64),
          'reg_dl'   => Register.on_id_bits(nil, 2, 8),
          'reg_dx'   => Register.on_id_bits(nil, 2, 16),
          'reg_edx'  => Register.on_id_bits(nil, 2, 32),
          'reg_rdx'  => Register.on_id_bits(nil, 2, 64),
          'reg_bl'   => Register.on_id_bits(nil, 3, 8),
          'reg_bx'   => Register.on_id_bits(nil, 3, 16),
          'reg_ebx'  => Register.on_id_bits(nil, 3, 32),
          'reg_rbx'  => Register.on_id_bits(nil, 3, 64),
          'reg_fs'   => SegmentRegister.on_id(nil, 4),
          'reg_gs'   => SegmentRegister.on_id(nil, 5),
          'reg32na'  => Register.new(32, nil, 0, true),
          'fpureg'   => FPURegister.new,
          'reg_creg' => ControlRegister.new,
          'reg_dreg' => DebugRegister.new,
          'reg_treg' => TestRegister.new,
          'reg_sreg' => SegmentRegister.new,
          'fpu0'     => FPURegister.new(0),
          'unity'    => Immediate.new(1, false, 1),
        }
      end
      return @simple_parameters[parameter] if @simple_parameters.key? parameter
      return parameter if parameter.start_with? 'rm' # Expanded later
      case parameter
      when /^imm(\d+)?$/       then return Immediate.new($1 && $1.to_i)
      when /^(.)byte(.)?word(\d+)?$/
        return Immediate.new(8, $1 == 's')
      when /^(.)dword(\d+)?$/
        return Immediate.new(16, $1 == 's')
      when /^reg(\d+)?$/       then return Register.new($1 && $1.to_i)
      when /^mem(\d+)?$/       then return Address.new(false, $1 && $1.to_i)
      when 'mem_offs'          then return Address.new(true)
      else
        warn "unknown parameter: #{parameter.inspect}"
        return parameter
      end
    end

    UNUSED_CODES = [
      # locks not used
      'hlexr', 'hlenl', 'hle',
      # otherwise unused (refer to nasm/asm/assemble.c)
      'norexb', 'norexx', 'norexr', 'norexw', 'odf', 'nof3', 'np',
      'jcc8', 'jmp8',
      # only 64-bit addressing used, we don't need this
      'a64'
    ].to_set
    def parse_command line
      return if line.empty? or line[0] == ';'
      if line =~ /^(\w+)\s+([^\s]*)\s+\[([rmij-]+:)?([^\]]*)\]/
        name, params, param_layout, ops = $1, $2, $3, $4
        
        params = params.split ','
        spec = nil
        if params == ["void"]
          params = []
        else
          params[0], spec = params[0].split '|'
        end
            
        param_layout ||= ''
        param_layout.tr! ':', ''
        
        ops = ops.split
        
        # only 64-bit addressing used
        return if ops.include? 'a32'
        
        # remove unused codes
        ops.delete_if do |cd|
          UNUSED_CODES.include? cd
        end
        
        command              = Command.new
        command.mnemonic     = name
        command.specifier    = spec
        command.param_layout = param_layout
        command.opcodes      = ops
        
        command.parameters = params.map { |pm| to_parameter pm }
        command.extract_sizes
        
        gen_commands = self.expand_parameters command
        if command.mnemonic.end_with? "cc"
          gen_commands = gen_commands.flat_map do |cmd|
            self.expand_conditional_commands cmd
          end
        end
        self.commands += gen_commands
      else
        raise "unable to parse line: #{line}"
      end
    end

    def parse
      Assembler.instruction_list.each_line do |line|
        self.parse_command line.strip
      end
      self.commands.each do |cmd|
        self.commands_by_mnemonic[cmd.mnemonic] ||= []
        self.commands_by_mnemonic[cmd.mnemonic] << cmd
      end
      self
    end
  end

  ##
  # Command is a potential command you can call. It has a
  # mnemonic (eg: MOV) and the memory format that it outputs as
  # (opcodes) as well as the kinds of parameters it takes and the
  # processor types that support the command.

  class Command
    attr_accessor :mnemonic, :specifier, :parameters, :param_layout, :opcodes
    attr_accessor :opsize
    attr_accessor :estimated_size
    def dup
      x            = super
      x.parameters = x.parameters.dup
      x.opcodes    = x.opcodes.dup
      x
    end
    
    def extract_sizes
      pos = [param_layout.index('i'), param_layout.index('j')].compact
      self.estimated_size = 0
      self.opsize = 8
      opcodes.each do |op|
        case op
        when 'o16'
          self.estimated_size += 1
          self.opsize = 16
        when 'o32'
          self.opsize = 32
        when 'o64'
          self.estimated_size += 1
          self.opsize = 64
        when 'o64nw'
          self.opsize = 64
        when /^[0-9a-f]{2}/, /^\//
          self.estimated_size += 1
        when 'ib'
          self.estimated_size += 1
          ppos = pos.shift
          parameters[ppos].bits = 8
          parameters[ppos].signed = nil
        when /^ib,(.)$/
          self.estimated_size += 1
          ppos = pos.shift
          parameters[ppos].bits = 8
          parameters[ppos].signed = $1 == 's'
        when 'iw'
          self.estimated_size += 2
          ppos = pos.shift
          parameters[ppos].bits = 16
          parameters[ppos].signed = nil
        when 'id'
          self.estimated_size += 4
          ppos = pos.shift
          parameters[ppos].bits = 32
          parameters[ppos].signed = nil
        when 'id,s'
          self.estimated_size += 4
          ppos = pos.shift
          parameters[ppos].bits = 32
          parameters[ppos].signed = true
        when 'iq'
          self.estimated_size += 8
          ppos = pos.shift
          parameters[ppos].bits = 64
          parameters[ppos].signed = nil
        when 'iwdq'
          # not an Immediate
          self.estimated_size += 8
        when 'rel'
          self.estimated_size += 4
          ppos = pos.shift
          parameters[ppos].bits = 32
          parameters[ppos].signed = true
        when 'rel8'
          self.estimated_size += 1
          ppos = pos.shift
          parameters[ppos].bits = 8
          parameters[ppos].signed = true
        end
      end
    end
    
    def parameter_applies? ip, cp, idx
      return false if cp.is_a? String

      if ip.register? && cp.register?
        return false if ip.bits != (cp.bits || self.opsize)
        unless cp.negative_match
          return cp.id.nil? || ip.id == cp.id
        else
          return ip.id != cp.id
        end
      end

      if ip.address? && cp.address?
        return false if ip.bits && ip.bits != (cp.bits || self.opsize)
        return !cp.no_modrm || ip.offset?
      end

      if ip.special_register? && cp.special_register?
        return ip.class == cp.class && (cp.id.nil? || ip.id == cp.id)
      end

      return false unless cp.immediate?

      if ip.immediate_value?
        return true if cp.value && cp.value == ip
        if cp.signed
          return ip >= -(1 << cp.bits-1) && ip < (1 << cp.bits-1)
        else
          return ip >= 0 && ip < (1 << cp.bits)
        end
      end

      if ip.label?
        return ip.future_label? ? cp.bits == 32 : ip.bits <= cp.bits
      end

      false
    end

    def instruction_applies? instruction
      return false if instruction.mnemonic != self.mnemonic
      return false if instruction.specifier && instruction.specifier != self.specifier
      return false if instruction.parameters.size != self.parameters.size

      instruction.parameters.zip(self.parameters, 0..2).all? do |ip, cp, idx|
        self.parameter_applies? ip, cp, idx
      end
    end

  end

  ##
  # Instruction is an instruction shape that we're going to match to
  # Commands to find out what we should write in to memory.

  class Instruction
    attr_accessor :mnemonic, :specifier, :machine, :parameters, :x64_mode

    def initialize message, machine
      self.machine = machine
      self.mnemonic, *self.parameters = message
      self.mnemonic = mnemonic.to_s.upcase
      self.specifier = nil

      self.parameters.delete_if do |par|
        if par.is_a? String or par.is_a? Symbol
          raise ArgumentError("multiple specifiers not allowed") if self.specifier
          self.specifier = par.to_s
          true
        end
      end

      self.parameters.map! do |par|
        if par.kind_of? Array
          Address.from_array par
        else par end
      end

      self.parameters.each do |par|
        par.machine = self.machine if par.operand?
      end
      self.x64_mode = false
    end

    def first
      parameters.first
    end

    def second
      parameters.second
    end

    def assemble
      return false unless machine.instructions_by_mnemonic.key? self.mnemonic
      commands = machine.instructions_by_mnemonic[self.mnemonic].select { |command|
        command.instruction_applies? self
      }

      return false if commands.empty?
      
      # Heuristically select "smallest" instruction
      command = commands.each.with_index.min_by { |comm, i| [comm.estimated_size, i] }.first

      encoder = InstructionEncoder.new command, self, machine
      machine.stream.concat(encoder.encode)
      true
    end
  end
  
  ##
  # InstructionEncoder is responsible for encoding instructions
  
  class InstructionEncoder
    attr_accessor :command, :instruction, :machine
    attr_accessor :prefixes, :rex, :opcode, :modrm, :sib, :disp, :imm
    attr_accessor :opsize, :addrsize
    def initialize command, instruction, machine
      @command, @instruction, @machine = command, instruction, machine
      @prefixes = []
      @rex      = nil
      @opcode   = []
      @modrm    = nil
      @sib      = nil
      @disp     = []
      @imm      = []
      @opsize = 8
      @addrsize = 64
    end
    
    def param_by_type c
      idx = command.param_layout.index c
      raise "param with type code #{c} not found" if idx.nil?
      instruction.parameters[idx]
    end
    
    def encode
      imm_types = ['i', 'j']
      command.opcodes.each do |op|
        case op
        when 'o16'
          @opsize = 16
          prefixes.append 0x66
        when 'o32'
          @opsize = 32
        when 'o64'
          @opsize = 64
          set_rex :w, true
        when 'o64nw'
          @opsize = 64
        when /([0-9a-f]{2})i/
          prefixes.append $1.hex
        when /\/(r|[0-7])/
          num = if $1 == 'r'
            register = param_by_type 'r'
            set_rex_reg :r, register
            register.id & 7
          else
            $1.hex
          end
          encode_modrm num
        when /^i([bwdq])(,.)?$/
          param = param_by_type imm_types.shift
          case $1
          when 'b'
            self.imm.push_B param
          when 'w'
            self.imm.push_W param
          when 'd'
            self.imm.push_D param
          when 'q'
            self.imm.push_Q param
          end
        when "iwdq"
          param = param_by_type imm_types.shift
          self.imm.push_Q param.offset
        when 'rel'
          param = param_by_type imm_types.shift
          if param.label?
            if param.future_label?
              param.add machine.stream.size + bytes.size
              param = 4
            else
              param = -(machine.stream.size + bytes.size + 4 - param.position)
            end
          end
          self.imm.push_D param
        when 'rel8'
          param = param_by_type imm_types.shift
          if param.label?
            raise "rel8 used for future label reference" if param.future_label?
            param = -(machine.stream.size + bytes.size + 1 - param.position)
          end
          self.imm.push_B param
        when /^([0-9a-f]{1,2})(\+r)?$/
          num = $1.hex
          if $2
            register = param_by_type 'r'
            set_rex_reg :b, register
            num += register.id & 7
          end
          self.opcode.push num
        else
          raise "unrecognized code #{op}"
        end
      end
      
      bytes
    end
    
    def use_rex
      self.rex = 0x40 if rex.nil?
    end
    
    REX_BIT = {b: 0, x: 1, r: 2, w: 3}
    def set_rex key, val
      use_rex
      bit = REX_BIT[key]
      val = val && val != 0 ? 1 : 0
      self.rex |= val << bit
    end
    
    def set_rex_reg key, register
      if register.id >= 8
        set_rex key, 1
      end
    end
    
    def encode_modrm reg_field
      self.modrm = 0
      set_modrm :reg, reg_field
      param = param_by_type 'm'
      if param.register?
        set_modrm :mod, 0b11
        set_rex_reg :b, param
        set_modrm :rm, param.id & 7
      elsif param.address?
        if param.sib_needed?
          set_modrm :rm, 0b100
          encode_sib param
        else
          disp_bits = param.disp_bits
          disp_bits = 8 if param.base.id & 7 == 0b101 && disp_bits == 0
          set_rex_reg :b, param.base
          set_modrm :rm, param.base.id & 7
          case disp_bits
          when 8
            set_modrm :mod, 0b01
            self.disp.push_B param.offset
          when 32
            set_modrm :mod, 0b10
            self.disp.push_D param.offset
          end
        end
      else
        raise "invalid modrm memory param"
      end
    end
    
    def encode_sib address
      self.sib = 0
      disp_bits = address.disp_bits
      if address.base.nil?
        set_sib :base, 0b101
        if address.index.nil?
          set_sib :index, 0b100
        else
          set_rex_reg :x, address.index
          set_sib :index, address.index.id & 7
          
          set_sib :scale, address.scale_code
        end
        self.disp.push_D address.offset
        return
      end
      
      if disp_bits == 0 && address.base.id & 7 == 0b101
        disp_bits = 8
      end
      
      if address.index.nil?
        set_sib :index, 0b100
      else
        set_rex_reg :x, address.index
        set_sib :index, address.index.id & 7
      end
      
      set_rex_reg :b, address.base
      set_sib :base, address.base.id & 7
      
      set_sib :scale, address.scale_code
      
      case disp_bits
      when 8
        set_modrm :mod, 0b01
        self.disp.push_B address.offset
      when 32
        set_modrm :mod, 0b10
        self.disp.push_D address.offset
      end
    end
    
    MODRM_SHIFT = {rm: 0, reg: 3, mod: 6}
    def set_modrm key, val
      bit = MODRM_SHIFT[key]
      self.modrm |= val << bit
    end
    
    SIB_SHIFT = {base: 0, index: 3, scale: 6}
    def set_sib key, val
      bit = SIB_SHIFT[key]
      self.sib |= val << bit
    end
  
    def bytes
      l = []
      l += prefixes
      l.append(rex) if rex
      l += opcode
      l.append(modrm) if modrm
      l.append(sib) if sib
      l += disp
      l += imm
      l
    end
  end

  ##
  # MachineCode is an abstract machine that has subclasses for each
  # concrete machine type that you can write assembly language for.
  # Right now this library only supports X86, so look at
  # MachineCodeX86 for more details on how to use it.

  $wilson_method_missing = false
  class MachineCode
    attr_accessor :stream, :procedure, :bits
    attr_accessor :instructions_by_mnemonic

    def initialize
      self.procedure  = nil
      self.bits       = self.default_bits
      self.stream     = []

      self.setup_machine
    end

    def inspect
      "#{self.class}#{stream.inspect}"
    end

    def method_missing msg, *args
      # prevent accidental recursion
      return super if $wilson_method_missing
      $wilson_method_missing = true
      super unless self.instruction_from_message(msg, *args).assemble
      $wilson_method_missing = false
    end

    def instruction_from_message msg, *args
      Instruction.new [msg, *args], self
    end

    def label
      Label.on_at(self, stream.size)
    end

    def flabel
      FutureLabel.on self
    end

    def assemble instruction
      # wtf?
      raise "no"
    end

    alias :setup_machine :subclass_responsibility
    alias :platform     :subclass_responsibility
    alias :default_bits  :subclass_responsibility
  end

  ##
  # MachineCodeX86 is a concrete implementation of a machine to create
  # X86 assembly code on.
  #
  # You can use this class in two ways:
  #
  # a) you can instantiate an instance and use its register variables
  #    to build up machine code in the @stream variable and then use
  #    those bytes in any way that you see fit, or
  #
  # b) you can make a subclass of this class much like you do with
  #    ExternalInterface and put methods on the class that will
  #    compile in to assembler code that can be called from Smalltalk
  #    code
  #
  # == Using MachineCodeX86 for scripting
  #
  # This is the long hand way of writing assembly code, since you
  # always include a receiver with every command.
  #
  #     asm = Assembler.MachineCodeX86.new
  #
  # Once you have an assembler, you can access the registers and send
  # commands to them, eg:
  #
  #     asm.eax.mov 1
  #
  # As you send the commands, the @stream will build up containing the
  # X86 assembler bytes you can use. You can use memory addresses in
  # your assembler code with the #m method, eg:
  #
  #     asm.eax.m.mov 1
  #
  # Once you are finished, you simply send:
  #
  #     asm.stream
  #
  # This will return you the stream of bytes.
  #
  # == Labels & Jumps
  #
  # You can do labels and jump to them using two different label
  # commands. The first is #label, which places a label jump point
  # immediately on call, eg:
  #
  #         label = asm.label
  #         label.jmp
  #
  # The other is a future label that can be placed at some future
  # point in the program and jumped too
  #
  #         label = asm.future_label
  #         asm.eax.xor asm.eax
  #         label.jmp
  #         asm.eax.inc
  #         label.plant
  #
  # You #plant the future label where you want it to actually be and
  # past references to it will be updated. Future labels will always
  # use a dword jmp so that there's space to fill in the command if
  # the jmp ends up being far.

  class MachineCodeX86 < MachineCode
    # registers-general-64bit
    attr_accessor :rax, :rbx, :rbp, :rsp, :rdi, :rsi, :rcx, :rdx
    
    attr_accessor :r8, :r9, :r10, :r11, :r12, :r13, :r14, :r15
    attr_accessor :r8d, :r9d, :r10d, :r11d, :r12d, :r13d, :r14d, :r15d
    attr_accessor :r8w, :r9w, :r10w, :r11w, :r12w, :r13w, :r14w, :r15w
    attr_accessor :r8b, :r9b, :r10b, :r11b, :r12b, :r13b, :r14b, :r15b
    
    # registers-general-32bit
    attr_accessor :eax, :ebx, :ebp, :esp, :edi, :esi, :ecx, :edx

    # registers-fpu
    attr_accessor :st0, :st1, :st2, :st3, :st4, :st5, :st6, :st7

    # registers-debug
    attr_accessor :dr0, :dr1, :dr2, :dr3, :dr6, :dr7

    # registers-segment
    attr_accessor :es, :ss, :cs, :gs, :fs, :ds

    # registers-test
    attr_accessor :tr3, :tr4, :tr5, :tr6, :tr7

    # registers-general-8bit
    attr_accessor :al, :ah, :bl, :bh, :cl, :ch, :dl, :dh

    # registers-general-16bit
    attr_accessor :ax, :bx, :cx, :dx, :sp, :bp, :si, :di

    # registers-control
    attr_accessor :cr0, :cr2, :cr3, :cr4

    def setup_machine
      self.instructions_by_mnemonic = Assembler.commands_by_mnemonic

      # 8-bit registers
      self.al = Register.on_id_bits self, 0, 8
      self.cl = Register.on_id_bits self, 1, 8
      self.dl = Register.on_id_bits self, 2, 8
      self.bl = Register.on_id_bits self, 3, 8
      self.ah = Register.on_id_bits self, 4, 8
      self.ch = Register.on_id_bits self, 5, 8
      self.dh = Register.on_id_bits self, 6, 8
      self.bh = Register.on_id_bits self, 7, 8
      
       self.r8b = Register.on_id_bits self, 8,  8
       self.r9b = Register.on_id_bits self, 9,  8
      self.r10b = Register.on_id_bits self, 10, 8
      self.r11b = Register.on_id_bits self, 11, 8
      self.r12b = Register.on_id_bits self, 12, 8
      self.r13b = Register.on_id_bits self, 13, 8
      self.r14b = Register.on_id_bits self, 14, 8
      self.r15b = Register.on_id_bits self, 15, 8
      
      # 16-bit registers
      self.ax = Register.on_id_bits self, 0, 16
      self.cx = Register.on_id_bits self, 1, 16
      self.dx = Register.on_id_bits self, 2, 16
      self.bx = Register.on_id_bits self, 3, 16
      self.sp = Register.on_id_bits self, 4, 16
      self.bp = Register.on_id_bits self, 5, 16
      self.si = Register.on_id_bits self, 6, 16
      self.di = Register.on_id_bits self, 7, 16
      
       self.r8w = Register.on_id_bits self, 8,  16
       self.r9w = Register.on_id_bits self, 9,  16
      self.r10w = Register.on_id_bits self, 10, 16
      self.r11w = Register.on_id_bits self, 11, 16
      self.r12w = Register.on_id_bits self, 12, 16
      self.r13w = Register.on_id_bits self, 13, 16
      self.r14w = Register.on_id_bits self, 14, 16
      self.r15w = Register.on_id_bits self, 15, 16
      
      # 32-bit registers
      self.eax = Register.on_id_bits self, 0, 32
      self.ecx = Register.on_id_bits self, 1, 32
      self.edx = Register.on_id_bits self, 2, 32
      self.ebx = Register.on_id_bits self, 3, 32
      self.esp = Register.on_id_bits self, 4, 32
      self.ebp = Register.on_id_bits self, 5, 32
      self.esi = Register.on_id_bits self, 6, 32
      self.edi = Register.on_id_bits self, 7, 32
      
       self.r8d = Register.on_id_bits self, 8,  32
       self.r9d = Register.on_id_bits self, 9,  32
      self.r10d = Register.on_id_bits self, 10, 32
      self.r11d = Register.on_id_bits self, 11, 32
      self.r12d = Register.on_id_bits self, 12, 32
      self.r13d = Register.on_id_bits self, 13, 32
      self.r14d = Register.on_id_bits self, 14, 32
      self.r15d = Register.on_id_bits self, 15, 32
      
      # 64-bit registers
      self.rax = Register.on_id_bits self, 0, 64
      self.rcx = Register.on_id_bits self, 1, 64
      self.rdx = Register.on_id_bits self, 2, 64
      self.rbx = Register.on_id_bits self, 3, 64
      self.rsp = Register.on_id_bits self, 4, 64
      self.rbp = Register.on_id_bits self, 5, 64
      self.rsi = Register.on_id_bits self, 6, 64
      self.rdi = Register.on_id_bits self, 7, 64
      
       self.r8 = Register.on_id_bits self, 8,  64
       self.r9 = Register.on_id_bits self, 9,  64
      self.r10 = Register.on_id_bits self, 10, 64
      self.r11 = Register.on_id_bits self, 11, 64
      self.r12 = Register.on_id_bits self, 12, 64
      self.r13 = Register.on_id_bits self, 13, 64
      self.r14 = Register.on_id_bits self, 14, 64
      self.r15 = Register.on_id_bits self, 15, 64
      
      # Segment registers
      self.es = SegmentRegister.on_id self, 0
      self.cs = SegmentRegister.on_id self, 1
      self.ss = SegmentRegister.on_id self, 2
      self.ds = SegmentRegister.on_id self, 3
      self.fs = SegmentRegister.on_id self, 4
      self.gs = SegmentRegister.on_id self, 5
      
      # Control registers
      self.cr0 = ControlRegister.on_id self, 0
      self.cr2 = ControlRegister.on_id self, 2
      self.cr3 = ControlRegister.on_id self, 3
      self.cr4 = ControlRegister.on_id self, 4
      
      # Test registers
      self.tr3 = TestRegister.on_id self, 3
      self.tr4 = TestRegister.on_id self, 4
      self.tr5 = TestRegister.on_id self, 5
      self.tr6 = TestRegister.on_id self, 6
      self.tr7 = TestRegister.on_id self, 7
      
      # Debug registers
      self.dr0 = DebugRegister.on_id self, 0
      self.dr1 = DebugRegister.on_id self, 1
      self.dr2 = DebugRegister.on_id self, 2
      self.dr3 = DebugRegister.on_id self, 3
      self.dr6 = DebugRegister.on_id self, 6
      self.dr7 = DebugRegister.on_id self, 7
      
      # FPU registers
      self.st0 = FPURegister.on_id self, 0
      self.st1 = FPURegister.on_id self, 1
      self.st2 = FPURegister.on_id self, 2
      self.st3 = FPURegister.on_id self, 3
      self.st4 = FPURegister.on_id self, 4
      self.st5 = FPURegister.on_id self, 5
      self.st6 = FPURegister.on_id self, 6
      self.st7 = FPURegister.on_id self, 7
    end
    
    def platform
      'x86_64'
    end

    def default_bits
      64
    end

    def syscall
      # Override Ruby's syscall
      method_missing :syscall
    end
    
    def test *args
      # Override Ruby's test
      method_missing :test, *args
    end
  end

  ##
  # Operand is any kind of operand used in a command or instruction,
  # eg: registers, memory addresses, labels, immediates, etc.

  class Operand
    attr_accessor :machine, :bits

    def self.on machine
      x = self.new
      x.machine = machine
      x
    end

    # TODO: fix _all_ initialize methods from here down to have cleaner args
    def initialize bits = nil, machine = nil
      @bits = bits
      @machine = machine
    end

    def method_missing msg, *args, &b
      # prevent accidental recursion
      return super if $wilson_method_missing
      $wilson_method_missing = true
      super unless self.instructionFromMessage(msg, *args, &b).assemble
      $wilson_method_missing = false
    end

    def instructionFromMessage msg, *args, &b
      Instruction.new [msg, self, *args] + (b ? [b] : []), machine
    end

    def operand?
      true
    end
  end

  ##
  # Immediate is an Integer wrapper so that we know the machine we're
  # dealing with when we apply commands

  class Immediate < Operand
    attr_accessor :value, :signed

    def initialize bits=nil, signed=nil, value=nil
      super(bits)
      self.signed = signed
      self.value = value
    end
    
    def immediate?
      true
    end
  end

  ##
  # Address is a memory address in one of the following example forms:
  #
  #     eax, ebx + ecx, eax + 5, 23545, edx + eax + 2312

  class Address < Operand
    attr_accessor :base, :index, :scale
    attr_accessor :offset
    attr_accessor :no_modrm
 
    def self.from_array arr
      address = self.new
      address.bits = nil
      arr.delete_if do |x|
        if x.is_a? Symbol
          case x
          when :b8
            address.bits = 8
          when :b16
            address.bits = 16
          when :b32
            address.bits = 32
          when :b64
            address.bits = 64
          else
            raise "unrecognized address specifier"
          end
        end
      end
      ints, regs = arr.partition { |x| x.is_a? Integer }
      address.offset = ints.sum
      raise "at most 2 registers allowed in addressing mode" if regs.size > 2
      address.machine = regs.first.to_reg.machine
      base, index = regs
      scale = nil
      base, index = index, base if base.is_a? Register::Scaled
      raise "only one scaled register allowed in addressing mode" if base.is_a? Register::Scaled
      if index.is_a? Register::Scaled
        index, scale = index.register, index.scale
      end
      raise "sp can't be index" if index && index.id == 0b0100
      address.base, address.index, address.scale = base, index, scale
      address
    end
    
    def initialize no_modrm = nil, bits = nil, base = nil
      super(bits)

      self.no_modrm = no_modrm
      self.base = base

      self.index = self.offset = self.scale = nil
    end
    
    def offset_bits
      case offset
      when 0
        0
      when -(1<<7)...(1<<7)
        8
      when -(1<<15)...(1<<15)
        16
      when -(1<<31)...(1<<31)
        32
      else
        64
      end
    end
    
    def disp_bits
      b = offset_bits
      raise "too large disp #{offset}" if b == 64
      b == 16 ? 32 : b
    end
    
    def scale_code
      case scale
      when nil, 1
        0b00
      when 2
        0b01
      when 4
        0b10
      when 8
        0b11
      end
    end
    
    def address?
      true
    end

    def offset?
      base.nil? && index.nil?
    end
    
    def sib_needed?
      return false if no_modrm
      return true if offset?
      return false if index.nil? && (base.id & 7 != 0b100)
      true
    end
  end

  ##
  # Register is a general X86 register, such as eax, ebx, ecx, edx,
  # etc...

  class Register < Operand
    attr_accessor :id
    
    # Any register except id when true
    attr_accessor :negative_match
    
    def self.on_id_bits machine, id, bits
      self.new bits, machine, id
    end

    def initialize bits = nil, machine = nil, id = nil, negative = nil
      super(bits, machine)
      self.id = id
      self.negative_match = negative
    end

    def memory_register?
      false
    end

    def register?
      true
    end

    def get address # TODO: test
      self.mov address
      self.mov [self]
    end

    def push_mod_rm_on spareRegister, stream
      stream << (0b11000000 + id + (spareRegister.id << 3))
    end

    # def m
    #   self + 0
    # end

    # def - offset
    #   self + -offset
    # end

    # def + offset
    #   Address.on_id_offset machine, id, offset
    # end
    
    def * scale
      scale == 1 ? self : Scaled.new(self, scale)
    end
    
    def to_reg
      self
    end
    
    class Scaled
      attr_accessor :register, :scale
      def initialize register, scale
        raise "scale not in 2, 4, 8" unless [2, 4, 8].include? scale
        self.register = register
        self.scale = scale
      end
      def to_reg
        register
      end
    end
  end

  ##
  # MemoryRegister is a regular Register, but the parser needs to know
  # if it is a primary or secondary register. This form is a private
  # secondary register. Use Register instead of this guy.

  # class MemoryRegister < Register
  #   def memory_register?
  #     true
  #   end
  # end

  ##
  # Label is a known point in the byte stream that we can jmp/loop back to.

  class Label < Operand
    attr_accessor :position

    def self.on_at machine, position
      label = self.new
      label.machine = machine
      label.position = position
      label
    end

    def bits
      distance = machine.stream.size - position

      # assuming length of short jump is 2 bytes, near jump at most 6 bytes
      # encoded value would be - distance - instruction length
      if distance + 2 <= (1<<7)
        8
      elsif distance + 6 <= (1<<31)
        32
      else
        raise "label too far"
      end
    end

    def label?
      true
    end
  end

  ##
  # FutureLabel is a label in memory that hasn't been defined yet and
  # will go back and fill in the appropriate memory bytes later

  class FutureLabel < Label
    attr_accessor :positions

    def initialize
      super
      self.positions = []
    end

    def plant
      self.position = machine.stream.size

      positions.each do |pos|
        size = machine.stream[pos]
        address = []
        case size
        when 1 then
          address.push_B(position - pos - 1)
        when 2 then
          address.push_W(position - pos - 2)
        when 4 then
          address.push_D(position - pos - 4)
        else
          raise "unhandled size #{size}"
        end

        machine.stream[pos...pos+size] = address
      end
    end

    def future_label?
      position.nil?
    end

    def add aPosition
      positions << aPosition
    end
  end

  ##
  # SpecialRegister is the abstract implementation of any kind of
  # register that isn't a general register, eg: segment registers, mmx
  # registers, fpu registers, etc...

  class SpecialRegister < Operand
    attr_accessor :id

    def self.on_id machine, id
      register = self.new
      register.machine = machine
      register.id = id
      register
    end

    def special_register?
      true
    end
  end

  ##
  # DebugRegister is an X86 DRx register

  class DebugRegister < SpecialRegister
  end

  ##
  # TestRegister is an X86 Test Register, TRx

  class TestRegister < SpecialRegister
  end

  ##
  # FPURegister is an X86 fpureg, STx

  class FPURegister < SpecialRegister
    def initialize id = nil
      super()
      self.id = id
    end
  end

  ##
  # ControlRegister is an X86 CRx register

  class ControlRegister < SpecialRegister
  end

  ##
  # SegmentRegister is an X86 segment register, eg: ss, cs, ds, es...

  class SegmentRegister < SpecialRegister
  end
end # module Wilson

require 'rbconfig'

class Integer
  def immediate_value?
    true
  end

  def inspect
    "0x#{to_s 16}"
  end if $DEBUG
end

class Array
  def second
    self[1]
  end

  def push_B integer
    self << (integer & 255)
  end
  
  def push_W integer
    self.concat [integer].pack("v").unpack("C2")
  end
  
  def push_D integer
    self.concat [integer].pack("V").unpack("C4")
  end

  def push_Q integer
    self.concat [integer & (1<<32)-1, integer >> 32].pack("VV").unpack("C8")
  end
end

class Module
  def defasm name, *args, &block
    fn = assemble(*args, &block)
    define_method(name, &fn)
  end
end

class Object
  def assemble *args, &block
    asm = Wilson::MachineCodeX86.new
    
    asm.rbp.push
    asm.rbp.mov asm.rsp

    size = asm.stream.size

    asm.instance_eval(&block)

    if asm.stream.size == size  # return nil
      warn "returning nil for #{self}"
      asm.rax.mov 0
    end

    asm.rbp.pop
    asm.ret

    code = asm.stream.pack("C*")

    if $DEBUG then
      path = "#{$$}.obj"
      File.open path, "wb" do |f|
        f.write code
      end

      puts code.unpack("C*").map { |n| "%02X" % n }.join(' ')
      system "ndisasm", "-b", "64", path

      File.unlink path
    end

    ptr = LibC.mmap_rwx code.size
    LibC.memcpy(ptr, code, code.size)
    if $DEBUG
      puts "To debug in GDB: disas #{ptr.to_i.inspect}, +#{code.size.inspect}"
      gets
    end
    Fiddle::Function.new(ptr, args, Fiddle::TYPE_LONG)
  end
  
  def asm(*args, &block)
    argtypes = args.map do |val|
      case val
      when String
        Fiddle::TYPE_VOIDP
      else
        Fiddle::INTEGER
      end
    end
    assemble(*argtypes, &block).call(*args)
  end
  
end

__END__
ADC mem,reg8 [mr: hle 10 /r]
ADC reg8,reg8 [mr: 10 /r]
ADC mem,reg16 [mr: hle o16 11 /r]
ADC reg16,reg16 [mr: o16 11 /r]
ADC mem,reg32 [mr: hle o32 11 /r]
ADC reg32,reg32 [mr: o32 11 /r]
ADC mem,reg64 [mr: hle o64 11 /r]
ADC reg64,reg64 [mr: o64 11 /r]
ADC reg8,mem [rm: 12 /r]
ADC reg8,reg8 [rm: 12 /r]
ADC reg16,mem [rm: o16 13 /r]
ADC reg16,reg16 [rm: o16 13 /r]
ADC reg32,mem [rm: o32 13 /r]
ADC reg32,reg32 [rm: o32 13 /r]
ADC reg64,mem [rm: o64 13 /r]
ADC reg64,reg64 [rm: o64 13 /r]
ADC rm16,imm8 [mi: hle o16 83 /2 ib,s]
ADC rm32,imm8 [mi: hle o32 83 /2 ib,s]
ADC rm64,imm8 [mi: hle o64 83 /2 ib,s]
ADC reg_al,imm [-i: 14 ib]
ADC reg_ax,sbyteword [mi: o16 83 /2 ib,s]
ADC reg_ax,imm [-i: o16 15 iw]
ADC reg_eax,sbytedword [mi: o32 83 /2 ib,s]
ADC reg_eax,imm [-i: o32 15 id]
ADC reg_rax,sbytedword [mi: o64 83 /2 ib,s]
ADC reg_rax,imm [-i: o64 15 id,s]
ADC rm8,imm [mi: hle 80 /2 ib]
ADC rm16,sbyteword [mi: hle o16 83 /2 ib,s]
ADC rm16,imm [mi: hle o16 81 /2 iw]
ADC rm32,sbytedword [mi: hle o32 83 /2 ib,s]
ADC rm32,imm [mi: hle o32 81 /2 id]
ADC rm64,sbytedword [mi: hle o64 83 /2 ib,s]
ADC rm64,imm [mi: hle o64 81 /2 id,s]
ADC mem,imm8 [mi: hle 80 /2 ib]
ADC mem,sbyteword16 [mi: hle o16 83 /2 ib,s]
ADC mem,imm16 [mi: hle o16 81 /2 iw]
ADC mem,sbytedword32 [mi: hle o32 83 /2 ib,s]
ADC mem,imm32 [mi: hle o32 81 /2 id]
ADD mem,reg8 [mr: hle 00 /r]
ADD reg8,reg8 [mr: 00 /r]
ADD mem,reg16 [mr: hle o16 01 /r]
ADD reg16,reg16 [mr: o16 01 /r]
ADD mem,reg32 [mr: hle o32 01 /r]
ADD reg32,reg32 [mr: o32 01 /r]
ADD mem,reg64 [mr: hle o64 01 /r]
ADD reg64,reg64 [mr: o64 01 /r]
ADD reg8,mem [rm: 02 /r]
ADD reg8,reg8 [rm: 02 /r]
ADD reg16,mem [rm: o16 03 /r]
ADD reg16,reg16 [rm: o16 03 /r]
ADD reg32,mem [rm: o32 03 /r]
ADD reg32,reg32 [rm: o32 03 /r]
ADD reg64,mem [rm: o64 03 /r]
ADD reg64,reg64 [rm: o64 03 /r]
ADD rm16,imm8 [mi: hle o16 83 /0 ib,s]
ADD rm32,imm8 [mi: hle o32 83 /0 ib,s]
ADD rm64,imm8 [mi: hle o64 83 /0 ib,s]
ADD reg_al,imm [-i: 04 ib]
ADD reg_ax,sbyteword [mi: o16 83 /0 ib,s]
ADD reg_ax,imm [-i: o16 05 iw]
ADD reg_eax,sbytedword [mi: o32 83 /0 ib,s]
ADD reg_eax,imm [-i: o32 05 id]
ADD reg_rax,sbytedword [mi: o64 83 /0 ib,s]
ADD reg_rax,imm [-i: o64 05 id,s]
ADD rm8,imm [mi: hle 80 /0 ib]
ADD rm16,sbyteword [mi: hle o16 83 /0 ib,s]
ADD rm16,imm [mi: hle o16 81 /0 iw]
ADD rm32,sbytedword [mi: hle o32 83 /0 ib,s]
ADD rm32,imm [mi: hle o32 81 /0 id]
ADD rm64,sbytedword [mi: hle o64 83 /0 ib,s]
ADD rm64,imm [mi: hle o64 81 /0 id,s]
ADD mem,imm8 [mi: hle 80 /0 ib]
ADD mem,sbyteword16 [mi: hle o16 83 /0 ib,s]
ADD mem,imm16 [mi: hle o16 81 /0 iw]
ADD mem,sbytedword32 [mi: hle o32 83 /0 ib,s]
ADD mem,imm32 [mi: hle o32 81 /0 id]
AND mem,reg8 [mr: hle 20 /r]
AND reg8,reg8 [mr: 20 /r]
AND mem,reg16 [mr: hle o16 21 /r]
AND reg16,reg16 [mr: o16 21 /r]
AND mem,reg32 [mr: hle o32 21 /r]
AND reg32,reg32 [mr: o32 21 /r]
AND mem,reg64 [mr: hle o64 21 /r]
AND reg64,reg64 [mr: o64 21 /r]
AND reg8,mem [rm: 22 /r]
AND reg8,reg8 [rm: 22 /r]
AND reg16,mem [rm: o16 23 /r]
AND reg16,reg16 [rm: o16 23 /r]
AND reg32,mem [rm: o32 23 /r]
AND reg32,reg32 [rm: o32 23 /r]
AND reg64,mem [rm: o64 23 /r]
AND reg64,reg64 [rm: o64 23 /r]
AND rm16,imm8 [mi: hle o16 83 /4 ib,s]
AND rm32,imm8 [mi: hle o32 83 /4 ib,s]
AND rm64,imm8 [mi: hle o64 83 /4 ib,s]
AND reg_al,imm [-i: 24 ib]
AND reg_ax,sbyteword [mi: o16 83 /4 ib,s]
AND reg_ax,imm [-i: o16 25 iw]
AND reg_eax,sbytedword [mi: o32 83 /4 ib,s]
AND reg_eax,imm [-i: o32 25 id]
AND reg_rax,sbytedword [mi: o64 83 /4 ib,s]
AND reg_rax,imm [-i: o64 25 id,s]
AND rm8,imm [mi: hle 80 /4 ib]
AND rm16,sbyteword [mi: hle o16 83 /4 ib,s]
AND rm16,imm [mi: hle o16 81 /4 iw]
AND rm32,sbytedword [mi: hle o32 83 /4 ib,s]
AND rm32,imm [mi: hle o32 81 /4 id]
AND rm64,sbytedword [mi: hle o64 83 /4 ib,s]
AND rm64,imm [mi: hle o64 81 /4 id,s]
AND mem,imm8 [mi: hle 80 /4 ib]
AND mem,sbyteword16 [mi: hle o16 83 /4 ib,s]
AND mem,imm16 [mi: hle o16 81 /4 iw]
AND mem,sbytedword32 [mi: hle o32 83 /4 ib,s]
AND mem,imm32 [mi: hle o32 81 /4 id]
BSF reg16,mem [rm: o16 nof3 0f bc /r]
BSF reg16,reg16 [rm: o16 nof3 0f bc /r]
BSF reg32,mem [rm: o32 nof3 0f bc /r]
BSF reg32,reg32 [rm: o32 nof3 0f bc /r]
BSF reg64,mem [rm: o64 nof3 0f bc /r]
BSF reg64,reg64 [rm: o64 nof3 0f bc /r]
BSR reg16,mem [rm: o16 nof3 0f bd /r]
BSR reg16,reg16 [rm: o16 nof3 0f bd /r]
BSR reg32,mem [rm: o32 nof3 0f bd /r]
BSR reg32,reg32 [rm: o32 nof3 0f bd /r]
BSR reg64,mem [rm: o64 nof3 0f bd /r]
BSR reg64,reg64 [rm: o64 nof3 0f bd /r]
BSWAP reg32 [r: o32 0f c8+r]
BSWAP reg64 [r: o64 0f c8+r]
BT mem,reg16 [mr: o16 0f a3 /r]
BT reg16,reg16 [mr: o16 0f a3 /r]
BT mem,reg32 [mr: o32 0f a3 /r]
BT reg32,reg32 [mr: o32 0f a3 /r]
BT mem,reg64 [mr: o64 0f a3 /r]
BT reg64,reg64 [mr: o64 0f a3 /r]
BT rm16,imm [mi: o16 0f ba /4 ib,u]
BT rm32,imm [mi: o32 0f ba /4 ib,u]
BT rm64,imm [mi: o64 0f ba /4 ib,u]
BTC mem,reg16 [mr: hle o16 0f bb /r]
BTC reg16,reg16 [mr: o16 0f bb /r]
BTC mem,reg32 [mr: hle o32 0f bb /r]
BTC reg32,reg32 [mr: o32 0f bb /r]
BTC mem,reg64 [mr: hle o64 0f bb /r]
BTC reg64,reg64 [mr: o64 0f bb /r]
BTC rm16,imm [mi: hle o16 0f ba /7 ib,u]
BTC rm32,imm [mi: hle o32 0f ba /7 ib,u]
BTC rm64,imm [mi: hle o64 0f ba /7 ib,u]
BTR mem,reg16 [mr: hle o16 0f b3 /r]
BTR reg16,reg16 [mr: o16 0f b3 /r]
BTR mem,reg32 [mr: hle o32 0f b3 /r]
BTR reg32,reg32 [mr: o32 0f b3 /r]
BTR mem,reg64 [mr: hle o64 0f b3 /r]
BTR reg64,reg64 [mr: o64 0f b3 /r]
BTR rm16,imm [mi: hle o16 0f ba /6 ib,u]
BTR rm32,imm [mi: hle o32 0f ba /6 ib,u]
BTR rm64,imm [mi: hle o64 0f ba /6 ib,u]
BTS mem,reg16 [mr: hle o16 0f ab /r]
BTS reg16,reg16 [mr: o16 0f ab /r]
BTS mem,reg32 [mr: hle o32 0f ab /r]
BTS reg32,reg32 [mr: o32 0f ab /r]
BTS mem,reg64 [mr: hle o64 0f ab /r]
BTS reg64,reg64 [mr: o64 0f ab /r]
BTS rm16,imm [mi: hle o16 0f ba /5 ib,u]
BTS rm32,imm [mi: hle o32 0f ba /5 ib,u]
BTS rm64,imm [mi: hle o64 0f ba /5 ib,u]
CALL imm [i: odf e8 rel]
CALL imm|near [i: odf e8 rel]
; Call/jmp near imm/reg/mem is always 64-bit in long mode.
CALL imm64 [i: o64nw e8 rel]
CALL imm64|near [i: o64nw e8 rel]
CALL mem|far [m: o64 ff /3]
CALL mem16|far [m: o16 ff /3]
CALL mem32|far [m: o32 ff /3]
CALL mem64|far [m: o64 ff /3]
CALL mem|near [m: odf ff /2]
CALL rm64|near [m: o64nw ff /2]
CALL mem [m: odf ff /2]
CALL rm64 [m: o64nw ff /2]

CBW void [ o16 98]
CDQ void [ o32 99]
CDQE void [ o64 98]
CLC void [ f8]
CLD void [ fc]
CLI void [ fa]
CLTS void [ 0f 06]
CMC void [ f5]
CMP mem,reg8 [mr: 38 /r]
CMP reg8,reg8 [mr: 38 /r]
CMP mem,reg16 [mr: o16 39 /r]
CMP reg16,reg16 [mr: o16 39 /r]
CMP mem,reg32 [mr: o32 39 /r]
CMP reg32,reg32 [mr: o32 39 /r]
CMP mem,reg64 [mr: o64 39 /r]
CMP reg64,reg64 [mr: o64 39 /r]
CMP reg8,mem [rm: 3a /r]
CMP reg8,reg8 [rm: 3a /r]
CMP reg16,mem [rm: o16 3b /r]
CMP reg16,reg16 [rm: o16 3b /r]
CMP reg32,mem [rm: o32 3b /r]
CMP reg32,reg32 [rm: o32 3b /r]
CMP reg64,mem [rm: o64 3b /r]
CMP reg64,reg64 [rm: o64 3b /r]
CMP rm16,imm8 [mi: o16 83 /7 ib,s]
CMP rm32,imm8 [mi: o32 83 /7 ib,s]
CMP rm64,imm8 [mi: o64 83 /7 ib,s]
CMP reg_al,imm [-i: 3c ib]
CMP reg_ax,sbyteword [mi: o16 83 /7 ib,s]
CMP reg_ax,imm [-i: o16 3d iw]
CMP reg_eax,sbytedword [mi: o32 83 /7 ib,s]
CMP reg_eax,imm [-i: o32 3d id]
CMP reg_rax,sbytedword [mi: o64 83 /7 ib,s]
CMP reg_rax,imm [-i: o64 3d id,s]
CMP rm8,imm [mi: 80 /7 ib]
CMP rm16,sbyteword [mi: o16 83 /7 ib,s]
CMP rm16,imm [mi: o16 81 /7 iw]
CMP rm32,sbytedword [mi: o32 83 /7 ib,s]
CMP rm32,imm [mi: o32 81 /7 id]
CMP rm64,sbytedword [mi: o64 83 /7 ib,s]
CMP rm64,imm [mi: o64 81 /7 id,s]
CMP mem,imm8 [mi: 80 /7 ib]
CMP mem,sbyteword16 [mi: o16 83 /7 ib,s]
CMP mem,imm16 [mi: o16 81 /7 iw]
CMP mem,sbytedword32 [mi: o32 83 /7 ib,s]
CMP mem,imm32 [mi: o32 81 /7 id]
CMPSB void [ repe a6]
CMPSD void [ repe o32 a7]
CMPSQ void [ repe o64 a7]
CMPSW void [ repe o16 a7]
CMPXCHG mem,reg8 [mr: hle 0f b0 /r]
CMPXCHG reg8,reg8 [mr: 0f b0 /r]
CMPXCHG mem,reg16 [mr: hle o16 0f b1 /r]
CMPXCHG reg16,reg16 [mr: o16 0f b1 /r]
CMPXCHG mem,reg32 [mr: hle o32 0f b1 /r]
CMPXCHG reg32,reg32 [mr: o32 0f b1 /r]
CMPXCHG mem,reg64 [mr: hle o64 0f b1 /r]
CMPXCHG reg64,reg64 [mr: o64 0f b1 /r]
CMPXCHG8B mem [m: hle norexw 0f c7 /1]
CMPXCHG16B mem [m: o64 0f c7 /1]
CPUID void [ 0f a2]
CPU_READ void [ 0f 3d]
CPU_WRITE void [ 0f 3c]
CQO void [ o64 99]
CWD void [ o16 99]
CWDE void [ o32 98]
DEC rm8 [m: hle fe /1]
DEC rm16 [m: hle o16 ff /1]
DEC rm32 [m: hle o32 ff /1]
DEC rm64 [m: hle o64 ff /1]
DIV rm8 [m: f6 /6]
DIV rm16 [m: o16 f7 /6]
DIV rm32 [m: o32 f7 /6]
DIV rm64 [m: o64 f7 /6]
DMINT void [ 0f 39]
ENTER imm,imm [ij: c8 iw ib,u]
F2XM1 void [ d9 f0]
FABS void [ d9 e1]
FADD mem32 [m: d8 /0]
FADD mem64 [m: dc /0]
FADD fpureg|to [r: dc c0+r]
FADD fpureg [r: d8 c0+r]
FADD fpureg,fpu0 [r-: dc c0+r]
FADD fpu0,fpureg [-r: d8 c0+r]
FADD void [ de c1]
FADDP fpureg [r: de c0+r]
FADDP fpureg,fpu0 [r-: de c0+r]
FADDP void [ de c1]
FBLD mem80 [m: df /4]
FBLD mem [m: df /4]
FBSTP mem80 [m: df /6]
FBSTP mem [m: df /6]
FCHS void [ d9 e0]
FCLEX void [ wait db e2]
FCMOVB fpureg [r: da c0+r]
FCMOVB fpu0,fpureg [-r: da c0+r]
FCMOVB void [ da c1]
FCMOVBE fpureg [r: da d0+r]
FCMOVBE fpu0,fpureg [-r: da d0+r]
FCMOVBE void [ da d1]
FCMOVE fpureg [r: da c8+r]
FCMOVE fpu0,fpureg [-r: da c8+r]
FCMOVE void [ da c9]
FCMOVNB fpureg [r: db c0+r]
FCMOVNB fpu0,fpureg [-r: db c0+r]
FCMOVNB void [ db c1]
FCMOVNBE fpureg [r: db d0+r]
FCMOVNBE fpu0,fpureg [-r: db d0+r]
FCMOVNBE void [ db d1]
FCMOVNE fpureg [r: db c8+r]
FCMOVNE fpu0,fpureg [-r: db c8+r]
FCMOVNE void [ db c9]
FCMOVNU fpureg [r: db d8+r]
FCMOVNU fpu0,fpureg [-r: db d8+r]
FCMOVNU void [ db d9]
FCMOVU fpureg [r: da d8+r]
FCMOVU fpu0,fpureg [-r: da d8+r]
FCMOVU void [ da d9]
FCOM mem32 [m: d8 /2]
FCOM mem64 [m: dc /2]
FCOM fpureg [r: d8 d0+r]
FCOM fpu0,fpureg [-r: d8 d0+r]
FCOM void [ d8 d1]
FCOMI fpureg [r: db f0+r]
FCOMI fpu0,fpureg [-r: db f0+r]
FCOMI void [ db f1]
FCOMIP fpureg [r: df f0+r]
FCOMIP fpu0,fpureg [-r: df f0+r]
FCOMIP void [ df f1]
FCOMP mem32 [m: d8 /3]
FCOMP mem64 [m: dc /3]
FCOMP fpureg [r: d8 d8+r]
FCOMP fpu0,fpureg [-r: d8 d8+r]
FCOMP void [ d8 d9]
FCOMPP void [ de d9]
FCOS void [ d9 ff]
FDECSTP void [ d9 f6]
FDISI void [ wait db e1]
FDIV mem32 [m: d8 /6]
FDIV mem64 [m: dc /6]
FDIV fpureg|to [r: dc f8+r]
FDIV fpureg [r: d8 f0+r]
FDIV fpureg,fpu0 [r-: dc f8+r]
FDIV fpu0,fpureg [-r: d8 f0+r]
FDIV void [ de f9]
FDIVP fpureg [r: de f8+r]
FDIVP fpureg,fpu0 [r-: de f8+r]
FDIVP void [ de f9]
FDIVR mem32 [m: d8 /7]
FDIVR mem64 [m: dc /7]
FDIVR fpureg|to [r: dc f0+r]
FDIVR fpureg,fpu0 [r-: dc f0+r]
FDIVR fpureg [r: d8 f8+r]
FDIVR fpu0,fpureg [-r: d8 f8+r]
FDIVR void [ de f1]
FDIVRP fpureg [r: de f0+r]
FDIVRP fpureg,fpu0 [r-: de f0+r]
FDIVRP void [ de f1]
FEMMS void [ 0f 0e]
FENI void [ wait db e0]
FFREE fpureg [r: dd c0+r]
FFREE void [ dd c1]
FFREEP fpureg [r: df c0+r]
FFREEP void [ df c1]
FIADD mem32 [m: da /0]
FIADD mem16 [m: de /0]
FICOM mem32 [m: da /2]
FICOM mem16 [m: de /2]
FICOMP mem32 [m: da /3]
FICOMP mem16 [m: de /3]
FIDIV mem32 [m: da /6]
FIDIV mem16 [m: de /6]
FIDIVR mem32 [m: da /7]
FIDIVR mem16 [m: de /7]
FILD mem32 [m: db /0]
FILD mem16 [m: df /0]
FILD mem64 [m: df /5]
FIMUL mem32 [m: da /1]
FIMUL mem16 [m: de /1]
FINCSTP void [ d9 f7]
FINIT void [ wait db e3]
FIST mem32 [m: db /2]
FIST mem16 [m: df /2]
FISTP mem32 [m: db /3]
FISTP mem16 [m: df /3]
FISTP mem64 [m: df /7]
FISTTP mem16 [m: df /1]
FISTTP mem32 [m: db /1]
FISTTP mem64 [m: dd /1]
FISUB mem32 [m: da /4]
FISUB mem16 [m: de /4]
FISUBR mem32 [m: da /5]
FISUBR mem16 [m: de /5]
FLD mem32 [m: d9 /0]
FLD mem64 [m: dd /0]
FLD mem80 [m: db /5]
FLD fpureg [r: d9 c0+r]
FLD void [ d9 c1]
FLD1 void [ d9 e8]
FLDCW mem [m: d9 /5]
FLDENV mem [m: d9 /4]
FLDL2E void [ d9 ea]
FLDL2T void [ d9 e9]
FLDLG2 void [ d9 ec]
FLDLN2 void [ d9 ed]
FLDPI void [ d9 eb]
FLDZ void [ d9 ee]
FMUL mem32 [m: d8 /1]
FMUL mem64 [m: dc /1]
FMUL fpureg|to [r: dc c8+r]
FMUL fpureg,fpu0 [r-: dc c8+r]
FMUL fpureg [r: d8 c8+r]
FMUL fpu0,fpureg [-r: d8 c8+r]
FMUL void [ de c9]
FMULP fpureg [r: de c8+r]
FMULP fpureg,fpu0 [r-: de c8+r]
FMULP void [ de c9]
FNCLEX void [ db e2]
FNDISI void [ db e1]
FNENI void [ db e0]
FNINIT void [ db e3]
FNOP void [ d9 d0]
FNSAVE mem [m: dd /6]
FNSTCW mem [m: d9 /7]
FNSTENV mem [m: d9 /6]
FNSTSW mem [m: dd /7]
FNSTSW reg_ax [-: df e0]
FPATAN void [ d9 f3]
FPREM void [ d9 f8]
FPREM1 void [ d9 f5]
FPTAN void [ d9 f2]
FRNDINT void [ d9 fc]
FRSTOR mem [m: dd /4]
FSAVE mem [m: wait dd /6]
FSCALE void [ d9 fd]
FSETPM void [ db e4]
FSIN void [ d9 fe]
FSINCOS void [ d9 fb]
FSQRT void [ d9 fa]
FST mem32 [m: d9 /2]
FST mem64 [m: dd /2]
FST fpureg [r: dd d0+r]
FST void [ dd d1]
FSTCW mem [m: wait d9 /7]
FSTENV mem [m: wait d9 /6]
FSTP mem32 [m: d9 /3]
FSTP mem64 [m: dd /3]
FSTP mem80 [m: db /7]
FSTP fpureg [r: dd d8+r]
FSTP void [ dd d9]
FSTSW mem [m: wait dd /7]
FSTSW reg_ax [-: wait df e0]
FSUB mem32 [m: d8 /4]
FSUB mem64 [m: dc /4]
FSUB fpureg|to [r: dc e8+r]
FSUB fpureg,fpu0 [r-: dc e8+r]
FSUB fpureg [r: d8 e0+r]
FSUB fpu0,fpureg [-r: d8 e0+r]
FSUB void [ de e9]
FSUBP fpureg [r: de e8+r]
FSUBP fpureg,fpu0 [r-: de e8+r]
FSUBP void [ de e9]
FSUBR mem32 [m: d8 /5]
FSUBR mem64 [m: dc /5]
FSUBR fpureg|to [r: dc e0+r]
FSUBR fpureg,fpu0 [r-: dc e0+r]
FSUBR fpureg [r: d8 e8+r]
FSUBR fpu0,fpureg [-r: d8 e8+r]
FSUBR void [ de e1]
FSUBRP fpureg [r: de e0+r]
FSUBRP fpureg,fpu0 [r-: de e0+r]
FSUBRP void [ de e1]
FTST void [ d9 e4]
FUCOM fpureg [r: dd e0+r]
FUCOM fpu0,fpureg [-r: dd e0+r]
FUCOM void [ dd e1]
FUCOMI fpureg [r: db e8+r]
FUCOMI fpu0,fpureg [-r: db e8+r]
FUCOMI void [ db e9]
FUCOMIP fpureg [r: df e8+r]
FUCOMIP fpu0,fpureg [-r: df e8+r]
FUCOMIP void [ df e9]
FUCOMP fpureg [r: dd e8+r]
FUCOMP fpu0,fpureg [-r: dd e8+r]
FUCOMP void [ dd e9]
FUCOMPP void [ da e9]
FXAM void [ d9 e5]
FXCH fpureg [r: d9 c8+r]
FXCH fpureg,fpu0 [r-: d9 c8+r]
FXCH fpu0,fpureg [-r: d9 c8+r]
FXCH void [ d9 c9]
FXTRACT void [ d9 f4]
FYL2X void [ d9 f1]
FYL2XP1 void [ d9 f9]
HLT void [ f4]
ICEBP void [ f1]
IDIV rm8 [m: f6 /7]
IDIV rm16 [m: o16 f7 /7]
IDIV rm32 [m: o32 f7 /7]
IDIV rm64 [m: o64 f7 /7]
IMUL rm8 [m: f6 /5]
IMUL rm16 [m: o16 f7 /5]
IMUL rm32 [m: o32 f7 /5]
IMUL rm64 [m: o64 f7 /5]
IMUL reg16,mem [rm: o16 0f af /r]
IMUL reg16,reg16 [rm: o16 0f af /r]
IMUL reg32,mem [rm: o32 0f af /r]
IMUL reg32,reg32 [rm: o32 0f af /r]
IMUL reg64,mem [rm: o64 0f af /r]
IMUL reg64,reg64 [rm: o64 0f af /r]
IMUL reg16,mem,imm8 [rmi: o16 6b /r ib,s]
IMUL reg16,mem,sbyteword [rmi: o16 6b /r ib,s]
IMUL reg16,mem,imm16 [rmi: o16 69 /r iw]
IMUL reg16,mem,imm [rmi: o16 69 /r iw]
IMUL reg16,reg16,imm8 [rmi: o16 6b /r ib,s]
IMUL reg16,reg16,sbyteword [rmi: o16 6b /r ib,s]
IMUL reg16,reg16,imm16 [rmi: o16 69 /r iw]
IMUL reg16,reg16,imm [rmi: o16 69 /r iw]
IMUL reg32,mem,imm8 [rmi: o32 6b /r ib,s]
IMUL reg32,mem,sbytedword [rmi: o32 6b /r ib,s]
IMUL reg32,mem,imm32 [rmi: o32 69 /r id]
IMUL reg32,mem,imm [rmi: o32 69 /r id]
IMUL reg32,reg32,imm8 [rmi: o32 6b /r ib,s]
IMUL reg32,reg32,sbytedword [rmi: o32 6b /r ib,s]
IMUL reg32,reg32,imm32 [rmi: o32 69 /r id]
IMUL reg32,reg32,imm [rmi: o32 69 /r id]
IMUL reg64,mem,imm8 [rmi: o64 6b /r ib,s]
IMUL reg64,mem,sbytedword [rmi: o64 6b /r ib,s]
IMUL reg64,mem,imm32 [rmi: o64 69 /r id]
IMUL reg64,mem,imm [rmi: o64 69 /r id,s]
IMUL reg64,reg64,imm8 [rmi: o64 6b /r ib,s]
IMUL reg64,reg64,sbytedword [rmi: o64 6b /r ib,s]
IMUL reg64,reg64,imm32 [rmi: o64 69 /r id]
IMUL reg64,reg64,imm [rmi: o64 69 /r id,s]
;omitting r+m (same parameter stored multiple times) support
;these can be replaced IMUL a,b --> IMUL a,a,b
;IMUL reg16,imm8 [r+mi: o16 6b /r ib,s]
;IMUL reg16,sbyteword [r+mi: o16 6b /r ib,s]
;IMUL reg16,imm16 [r+mi: o16 69 /r iw]
;IMUL reg16,imm [r+mi: o16 69 /r iw]
;IMUL reg32,imm8 [r+mi: o32 6b /r ib,s]
;IMUL reg32,sbytedword [r+mi: o32 6b /r ib,s]
;IMUL reg32,imm32 [r+mi: o32 69 /r id]
;IMUL reg32,imm [r+mi: o32 69 /r id]
;IMUL reg64,imm8 [r+mi: o64 6b /r ib,s]
;IMUL reg64,sbytedword [r+mi: o64 6b /r ib,s]
;IMUL reg64,imm32 [r+mi: o64 69 /r id,s]
;IMUL reg64,imm [r+mi: o64 69 /r id,s]
IN reg_al,imm [-i: e4 ib,u]
IN reg_ax,imm [-i: o16 e5 ib,u]
IN reg_eax,imm [-i: o32 e5 ib,u]
IN reg_al,reg_dx [--: ec]
IN reg_ax,reg_dx [--: o16 ed]
IN reg_eax,reg_dx [--: o32 ed]
INC rm8 [m: hle fe /0]
INC rm16 [m: hle o16 ff /0]
INC rm32 [m: hle o32 ff /0]
INC rm64 [m: hle o64 ff /0]
INSB void [ 6c]
INSD void [ o32 6d]
INSW void [ o16 6d]
INT imm [i: cd ib,u]
INT01 void [ f1]
INT1 void [ f1]
INT03 void [ cc]
INT3 void [ cc]
INVD void [ 0f 08]
INVPCID reg64,mem128 [rm: 66 0f 38 82 /r]
INVLPG mem [m: 0f 01 /7]
INVLPGA reg_eax,reg_ecx [--: a32 0f 01 df]
INVLPGA reg_rax,reg_ecx [--: o64nw a64 0f 01 df]
INVLPGA void [ 0f 01 df]
IRET void [ odf cf]
IRETD void [ o32 cf]
IRETQ void [ o64 cf]
IRETW void [ o16 cf]
JECXZ imm [i: a32 e3 rel8]
JRCXZ imm [i: a64 e3 rel8]
JMP imm|short [i: eb rel8]
JMP imm [i: jmp8 eb rel8]
JMP imm [i: odf e9 rel]
JMP imm|near [i: odf e9 rel]
; Call/jmp near imm/reg/mem is always 64-bit in long mode.
JMP imm64 [i: o64nw e9 rel]
JMP imm64|near [i: o64nw e9 rel]
JMP mem|far [m: o64 ff /5]
JMP mem16|far [m: o16 ff /5]
JMP mem32|far [m: o32 ff /5]
JMP mem64|far [m: o64 ff /5]
JMP mem|near [m: odf ff /4]
JMP rm64|near [m: o64nw ff /4]
JMP mem [m: odf ff /4]
JMP rm64 [m: o64nw ff /4]

JMPE imm [i: odf 0f b8 rel]
JMPE imm16 [i: o16 0f b8 rel]
JMPE imm32 [i: o32 0f b8 rel]
JMPE rm16 [m: o16 0f 00 /6]
JMPE rm32 [m: o32 0f 00 /6]
LAHF void [ 9f]
LAR reg16,mem [rm: o16 0f 02 /r]
LAR reg16,reg16 [rm: o16 0f 02 /r]
LAR reg16,reg32 [rm: o16 0f 02 /r]
LAR reg16,reg64 [rm: o16 o64nw 0f 02 /r]
LAR reg32,mem [rm: o32 0f 02 /r]
LAR reg32,reg16 [rm: o32 0f 02 /r]
LAR reg32,reg32 [rm: o32 0f 02 /r]
LAR reg32,reg64 [rm: o32 o64nw 0f 02 /r]
LAR reg64,mem [rm: o64 0f 02 /r]
LAR reg64,reg16 [rm: o64 0f 02 /r]
LAR reg64,reg32 [rm: o64 0f 02 /r]
LAR reg64,reg64 [rm: o64 0f 02 /r]
LEA reg16,mem [rm: o16 8d /r]
LEA reg32,mem [rm: o32 8d /r]
LEA reg64,mem [rm: o64 8d /r]
LEAVE void [ c9]
LFENCE void [ np 0f ae e8]
LFS reg16,mem [rm: o16 0f b4 /r]
LFS reg32,mem [rm: o32 0f b4 /r]
LFS reg64,mem [rm: o64 0f b4 /r]
LGDT mem [m: 0f 01 /2]
LGS reg16,mem [rm: o16 0f b5 /r]
LGS reg32,mem [rm: o32 0f b5 /r]
LGS reg64,mem [rm: o64 0f b5 /r]
LIDT mem [m: 0f 01 /3]
LLDT mem [m: 0f 00 /2]
LLDT mem16 [m: 0f 00 /2]
LLDT reg16 [m: 0f 00 /2]
LMSW mem [m: 0f 01 /6]
LMSW mem16 [m: 0f 01 /6]
LMSW reg16 [m: 0f 01 /6]
LODSB void [ ac]
LODSD void [ o32 ad]
LODSQ void [ o64 ad]
LODSW void [ o16 ad]
LOOP imm [i: adf e2 rel8]
LOOP imm,reg_ecx [i-: a32 e2 rel8]
LOOP imm,reg_rcx [i-: a64 e2 rel8]
LOOPE imm [i: adf e1 rel8]
LOOPE imm,reg_ecx [i-: a32 e1 rel8]
LOOPE imm,reg_rcx [i-: a64 e1 rel8]
LOOPNE imm [i: adf e0 rel8]
LOOPNE imm,reg_ecx [i-: a32 e0 rel8]
LOOPNE imm,reg_rcx [i-: a64 e0 rel8]
LOOPNZ imm [i: adf e0 rel8]
LOOPNZ imm,reg_ecx [i-: a32 e0 rel8]
LOOPNZ imm,reg_rcx [i-: a64 e0 rel8]
LOOPZ imm [i: adf e1 rel8]
LOOPZ imm,reg_ecx [i-: a32 e1 rel8]
LOOPZ imm,reg_rcx [i-: a64 e1 rel8]
LSL reg16,mem [rm: o16 0f 03 /r]
LSL reg16,reg16 [rm: o16 0f 03 /r]
LSL reg16,reg32 [rm: o16 0f 03 /r]
LSL reg16,reg64 [rm: o16 o64nw 0f 03 /r]
LSL reg32,mem [rm: o32 0f 03 /r]
LSL reg32,reg16 [rm: o32 0f 03 /r]
LSL reg32,reg32 [rm: o32 0f 03 /r]
LSL reg32,reg64 [rm: o32 o64nw 0f 03 /r]
LSL reg64,mem [rm: o64 0f 03 /r]
LSL reg64,reg16 [rm: o64 0f 03 /r]
LSL reg64,reg32 [rm: o64 0f 03 /r]
LSL reg64,reg64 [rm: o64 0f 03 /r]
LSS reg16,mem [rm: o16 0f b2 /r]
LSS reg32,mem [rm: o32 0f b2 /r]
LSS reg64,mem [rm: o64 0f b2 /r]
LTR mem [m: 0f 00 /3]
LTR mem16 [m: 0f 00 /3]
LTR reg16 [m: 0f 00 /3]
MFENCE void [ np 0f ae f0]
MONITOR void [ 0f 01 c8]
MONITOR reg_rax,reg_ecx,reg_edx [---: 0f 01 c8]
MONITORX void [ 0f 01 fa]
MONITORX reg_rax,reg_ecx,reg_edx [---: 0f 01 fa]
MONITORX reg_eax,reg_ecx,reg_edx [---: 0f 01 fa]
MONITORX reg_ax,reg_ecx,reg_edx [---: 0f 01 fa]
MOV mem,reg_sreg [mr: 8c /r]
MOV reg16,reg_sreg [mr: o16 8c /r]
MOV reg32,reg_sreg [mr: o32 8c /r]
;instructions flagged OPT seem to be invalid (in my env)? ;; ollpu
;MOV reg64,reg_sreg [mr: o64nw 8c /r]
MOV rm64,reg_sreg [mr: o64 8c /r]
MOV reg_sreg,mem [rm: 8e /r]
;MOV reg_sreg,reg16 [rm: 8e /r]
;MOV reg_sreg,reg32 [rm: 8e /r]
;MOV reg_sreg,reg64 [rm: o64nw 8e /r]
MOV reg_sreg,reg16 [rm: o16 8e /r]
MOV reg_sreg,reg32 [rm: o32 8e /r]
MOV reg_sreg,rm64 [rm: o64 8e /r]
MOV reg_al,mem_offs [-i: a0 iwdq]
MOV reg_ax,mem_offs [-i: o16 a1 iwdq]
MOV reg_eax,mem_offs [-i: o32 a1 iwdq]
MOV reg_rax,mem_offs [-i: o64 a1 iwdq]
MOV mem_offs,reg_al [i-: a2 iwdq]
MOV mem_offs,reg_ax [i-: o16 a3 iwdq]
MOV mem_offs,reg_eax [i-: o32 a3 iwdq]
MOV mem_offs,reg_rax [i-: o64 a3 iwdq]
MOV reg64,reg_creg [mr: o64nw 0f 20 /r]
MOV reg_creg,reg64 [rm: o64nw 0f 22 /r]
MOV reg64,reg_dreg [mr: o64nw 0f 21 /r]
MOV reg_dreg,reg64 [rm: o64nw 0f 23 /r]
MOV mem,reg8 [mr: hlexr 88 /r]
MOV reg8,reg8 [mr: 88 /r]
MOV mem,reg16 [mr: hlexr o16 89 /r]
MOV reg16,reg16 [mr: o16 89 /r]
MOV mem,reg32 [mr: hlexr o32 89 /r]
MOV reg32,reg32 [mr: o32 89 /r]
MOV mem,reg64 [mr: hlexr o64 89 /r]
MOV reg64,reg64 [mr: o64 89 /r]
MOV reg8,mem [rm: 8a /r]
MOV reg8,reg8 [rm: 8a /r]
MOV reg16,mem [rm: o16 8b /r]
MOV reg16,reg16 [rm: o16 8b /r]
MOV reg32,mem [rm: o32 8b /r]
MOV reg32,reg32 [rm: o32 8b /r]
MOV reg64,mem [rm: o64 8b /r]
MOV reg64,reg64 [rm: o64 8b /r]
MOV reg8,imm [ri: b0+r ib]
MOV reg16,imm [ri: o16 b8+r iw]
MOV reg32,imm [ri: o32 b8+r id]
;MOV reg64,udword [ri: o64nw b8+r id]
;MOV reg64,sdword [mi: o64 c7 /0 id,s]
MOV reg64,imm [ri: o64 b8+r iq]
MOV rm8,imm [mi: hlexr c6 /0 ib]
MOV rm16,imm [mi: hlexr o16 c7 /0 iw]
MOV rm32,imm [mi: hlexr o32 c7 /0 id]
MOV rm64,imm [mi: hlexr o64 c7 /0 id,s]
MOV rm64,imm32 [mi: hlexr o64 c7 /0 id,s]
MOV mem,imm8 [mi: hlexr c6 /0 ib]
MOV mem,imm16 [mi: hlexr o16 c7 /0 iw]
MOV mem,imm32 [mi: hlexr o32 c7 /0 id]
MOVSB void [ a4]
MOVSD void [ o32 a5]
MOVSQ void [ o64 a5]
MOVSW void [ o16 a5]
MOVSX reg16,mem [rm: o16 0f be /r]
MOVSX reg16,reg8 [rm: o16 0f be /r]
MOVSX reg32,rm8 [rm: o32 0f be /r]
MOVSX reg32,rm16 [rm: o32 0f bf /r]
MOVSX reg64,rm8 [rm: o64 0f be /r]
MOVSX reg64,rm16 [rm: o64 0f bf /r]
MOVSXD reg64,rm32 [rm: o64 63 /r]
MOVSX reg64,rm32 [rm: o64 63 /r]
MOVZX reg16,mem [rm: o16 0f b6 /r]
MOVZX reg16,reg8 [rm: o16 0f b6 /r]
MOVZX reg32,rm8 [rm: o32 0f b6 /r]
MOVZX reg32,rm16 [rm: o32 0f b7 /r]
MOVZX reg64,rm8 [rm: o64 0f b6 /r]
MOVZX reg64,rm16 [rm: o64 0f b7 /r]
MUL rm8 [m: f6 /4]
MUL rm16 [m: o16 f7 /4]
MUL rm32 [m: o32 f7 /4]
MUL rm64 [m: o64 f7 /4]
MWAIT void [ 0f 01 c9]
MWAIT reg_eax,reg_ecx [--: 0f 01 c9]
MWAITX void [ 0f 01 fb]
MWAITX reg_eax,reg_ecx [--: 0f 01 fb]
NEG rm8 [m: hle f6 /3]
NEG rm16 [m: hle o16 f7 /3]
NEG rm32 [m: hle o32 f7 /3]
NEG rm64 [m: hle o64 f7 /3]
NOP void [ norexb nof3 90]
NOP rm16 [m: o16 0f 1f /0]
NOP rm32 [m: o32 0f 1f /0]
NOP rm64 [m: o64 0f 1f /0]
NOT rm8 [m: hle f6 /2]
NOT rm16 [m: hle o16 f7 /2]
NOT rm32 [m: hle o32 f7 /2]
NOT rm64 [m: hle o64 f7 /2]
OR mem,reg8 [mr: hle 08 /r]
OR reg8,reg8 [mr: 08 /r]
OR mem,reg16 [mr: hle o16 09 /r]
OR reg16,reg16 [mr: o16 09 /r]
OR mem,reg32 [mr: hle o32 09 /r]
OR reg32,reg32 [mr: o32 09 /r]
OR mem,reg64 [mr: hle o64 09 /r]
OR reg64,reg64 [mr: o64 09 /r]
OR reg8,mem [rm: 0a /r]
OR reg8,reg8 [rm: 0a /r]
OR reg16,mem [rm: o16 0b /r]
OR reg16,reg16 [rm: o16 0b /r]
OR reg32,mem [rm: o32 0b /r]
OR reg32,reg32 [rm: o32 0b /r]
OR reg64,mem [rm: o64 0b /r]
OR reg64,reg64 [rm: o64 0b /r]
OR rm16,imm8 [mi: hle o16 83 /1 ib,s]
OR rm32,imm8 [mi: hle o32 83 /1 ib,s]
OR rm64,imm8 [mi: hle o64 83 /1 ib,s]
OR reg_al,imm [-i: 0c ib]
OR reg_ax,sbyteword [mi: o16 83 /1 ib,s]
OR reg_ax,imm [-i: o16 0d iw]
OR reg_eax,sbytedword [mi: o32 83 /1 ib,s]
OR reg_eax,imm [-i: o32 0d id]
OR reg_rax,sbytedword [mi: o64 83 /1 ib,s]
OR reg_rax,imm [-i: o64 0d id,s]
OR rm8,imm [mi: hle 80 /1 ib]
OR rm16,sbyteword [mi: hle o16 83 /1 ib,s]
OR rm16,imm [mi: hle o16 81 /1 iw]
OR rm32,sbytedword [mi: hle o32 83 /1 ib,s]
OR rm32,imm [mi: hle o32 81 /1 id]
OR rm64,sbytedword [mi: hle o64 83 /1 ib,s]
OR rm64,imm [mi: hle o64 81 /1 id,s]
OR mem,imm8 [mi: hle 80 /1 ib]
OR mem,sbyteword16 [mi: hle o16 83 /1 ib,s]
OR mem,imm16 [mi: hle o16 81 /1 iw]
OR mem,sbytedword32 [mi: hle o32 83 /1 ib,s]
OR mem,imm32 [mi: hle o32 81 /1 id]
OUT imm,reg_al [i-: e6 ib,u]
OUT imm,reg_ax [i-: o16 e7 ib,u]
OUT imm,reg_eax [i-: o32 e7 ib,u]
OUT reg_dx,reg_al [--: ee]
OUT reg_dx,reg_ax [--: o16 ef]
OUT reg_dx,reg_eax [--: o32 ef]
OUTSB void [ 6e]
OUTSD void [ o32 6f]
OUTSW void [ o16 6f]
PAUSE void [ f3i 90]
POP reg16 [r: o16 58+r]
POP reg64 [r: o64nw 58+r]
POP rm16 [m: o16 8f /0]
POP rm64 [m: o64nw 8f /0]
POP reg_fs [-: 0f a1]
POP reg_gs [-: 0f a9]
POPF void [ odf 9d]
POPFQ void [ o32 9d]
POPFW void [ o16 9d]
PREFETCH mem [m: 0f 0d /0]
PREFETCHW mem [m: 0f 0d /1]
PUSH reg16 [r: o16 50+r]
PUSH reg64 [r: o64nw 50+r]
PUSH rm16 [m: o16 ff /6]
PUSH rm64 [m: o64nw ff /6]
PUSH reg_fs [-: 0f a0]
PUSH reg_gs [-: 0f a8]
PUSH imm8 [i: 6a ib,s]
PUSH sbyteword16 [i: o16 6a ib,s]
PUSH imm16 [i: o16 68 iw]
PUSH sbytedword64 [i: o64nw 6a ib,s]
PUSH imm64 [i: o64nw 68 id,s]
PUSH sbytedword32 [i: o64nw 6a ib,s]
PUSH imm32 [i: o64nw 68 id,s]
PUSHF void [ odf 9c]
PUSHFQ void [ o32 9c]
PUSHFW void [ o16 9c]
RCL rm8,unity [m-: d0 /2]
RCL rm8,reg_cl [m-: d2 /2]
RCL rm8,imm8 [mi: c0 /2 ib,u]
RCL rm16,unity [m-: o16 d1 /2]
RCL rm16,reg_cl [m-: o16 d3 /2]
RCL rm16,imm8 [mi: o16 c1 /2 ib,u]
RCL rm32,unity [m-: o32 d1 /2]
RCL rm32,reg_cl [m-: o32 d3 /2]
RCL rm32,imm8 [mi: o32 c1 /2 ib,u]
RCL rm64,unity [m-: o64 d1 /2]
RCL rm64,reg_cl [m-: o64 d3 /2]
RCL rm64,imm8 [mi: o64 c1 /2 ib,u]
RCR rm8,unity [m-: d0 /3]
RCR rm8,reg_cl [m-: d2 /3]
RCR rm8,imm8 [mi: c0 /3 ib,u]
RCR rm16,unity [m-: o16 d1 /3]
RCR rm16,reg_cl [m-: o16 d3 /3]
RCR rm16,imm8 [mi: o16 c1 /3 ib,u]
RCR rm32,unity [m-: o32 d1 /3]
RCR rm32,reg_cl [m-: o32 d3 /3]
RCR rm32,imm8 [mi: o32 c1 /3 ib,u]
RCR rm64,unity [m-: o64 d1 /3]
RCR rm64,reg_cl [m-: o64 d3 /3]
RCR rm64,imm8 [mi: o64 c1 /3 ib,u]
RDSHR rm32 [m: o32 0f 36 /0]
RDMSR void [ 0f 32]
RDPMC void [ 0f 33]
RDTSC void [ 0f 31]
RDTSCP void [ 0f 01 f9]
RET void [ c3]
RET imm [i: c2 iw]
RETF void [ cb]
RETF imm [i: ca iw]
RETN void [ c3]
RETN imm [i: c2 iw]
RETW void [ o16 c3]
RETW imm [i: c2 iw]
RETFW void [ o16 cb]
RETFW imm [i: o16 ca iw]
RETNW void [ o16 c3]
RETNW imm [i: o16 c2 iw]
RETFD void [ o32 cb]
RETFD imm [i: o32 ca iw]
RETQ void [ o64nw c3]
RETQ imm [i: o64nw c2 iw]
RETFQ void [ o64 cb]
RETFQ imm [i: o64 ca iw]
RETNQ void [ o64nw c3]
RETNQ imm [i: o64nw c2 iw]

ROL rm8,unity [m-: d0 /0]
ROL rm8,reg_cl [m-: d2 /0]
ROL rm8,imm8 [mi: c0 /0 ib,u]
ROL rm16,unity [m-: o16 d1 /0]
ROL rm16,reg_cl [m-: o16 d3 /0]
ROL rm16,imm8 [mi: o16 c1 /0 ib,u]
ROL rm32,unity [m-: o32 d1 /0]
ROL rm32,reg_cl [m-: o32 d3 /0]
ROL rm32,imm8 [mi: o32 c1 /0 ib,u]
ROL rm64,unity [m-: o64 d1 /0]
ROL rm64,reg_cl [m-: o64 d3 /0]
ROL rm64,imm8 [mi: o64 c1 /0 ib,u]
ROR rm8,unity [m-: d0 /1]
ROR rm8,reg_cl [m-: d2 /1]
ROR rm8,imm8 [mi: c0 /1 ib,u]
ROR rm16,unity [m-: o16 d1 /1]
ROR rm16,reg_cl [m-: o16 d3 /1]
ROR rm16,imm8 [mi: o16 c1 /1 ib,u]
ROR rm32,unity [m-: o32 d1 /1]
ROR rm32,reg_cl [m-: o32 d3 /1]
ROR rm32,imm8 [mi: o32 c1 /1 ib,u]
ROR rm64,unity [m-: o64 d1 /1]
ROR rm64,reg_cl [m-: o64 d3 /1]
ROR rm64,imm8 [mi: o64 c1 /1 ib,u]
RDM void [ 0f 3a]
RSDC reg_sreg,mem80 [rm: 0f 79 /r]
RSLDT mem80 [m: 0f 7b /0]
RSM void [ 0f aa]
RSTS mem80 [m: 0f 7d /0]
SAHF void [ 9e]
SAL rm8,unity [m-: d0 /4]
SAL rm8,reg_cl [m-: d2 /4]
SAL rm8,imm8 [mi: c0 /4 ib,u]
SAL rm16,unity [m-: o16 d1 /4]
SAL rm16,reg_cl [m-: o16 d3 /4]
SAL rm16,imm8 [mi: o16 c1 /4 ib,u]
SAL rm32,unity [m-: o32 d1 /4]
SAL rm32,reg_cl [m-: o32 d3 /4]
SAL rm32,imm8 [mi: o32 c1 /4 ib,u]
SAL rm64,unity [m-: o64 d1 /4]
SAL rm64,reg_cl [m-: o64 d3 /4]
SAL rm64,imm8 [mi: o64 c1 /4 ib,u]
SALC void [ d6]
SAR rm8,unity [m-: d0 /7]
SAR rm8,reg_cl [m-: d2 /7]
SAR rm8,imm8 [mi: c0 /7 ib,u]
SAR rm16,unity [m-: o16 d1 /7]
SAR rm16,reg_cl [m-: o16 d3 /7]
SAR rm16,imm8 [mi: o16 c1 /7 ib,u]
SAR rm32,unity [m-: o32 d1 /7]
SAR rm32,reg_cl [m-: o32 d3 /7]
SAR rm32,imm8 [mi: o32 c1 /7 ib,u]
SAR rm64,unity [m-: o64 d1 /7]
SAR rm64,reg_cl [m-: o64 d3 /7]
SAR rm64,imm8 [mi: o64 c1 /7 ib,u]
SBB mem,reg8 [mr: hle 18 /r]
SBB reg8,reg8 [mr: 18 /r]
SBB mem,reg16 [mr: hle o16 19 /r]
SBB reg16,reg16 [mr: o16 19 /r]
SBB mem,reg32 [mr: hle o32 19 /r]
SBB reg32,reg32 [mr: o32 19 /r]
SBB mem,reg64 [mr: hle o64 19 /r]
SBB reg64,reg64 [mr: o64 19 /r]
SBB reg8,mem [rm: 1a /r]
SBB reg8,reg8 [rm: 1a /r]
SBB reg16,mem [rm: o16 1b /r]
SBB reg16,reg16 [rm: o16 1b /r]
SBB reg32,mem [rm: o32 1b /r]
SBB reg32,reg32 [rm: o32 1b /r]
SBB reg64,mem [rm: o64 1b /r]
SBB reg64,reg64 [rm: o64 1b /r]
SBB rm16,imm8 [mi: hle o16 83 /3 ib,s]
SBB rm32,imm8 [mi: hle o32 83 /3 ib,s]
SBB rm64,imm8 [mi: hle o64 83 /3 ib,s]
SBB reg_al,imm [-i: 1c ib]
SBB reg_ax,sbyteword [mi: o16 83 /3 ib,s]
SBB reg_ax,imm [-i: o16 1d iw]
SBB reg_eax,sbytedword [mi: o32 83 /3 ib,s]
SBB reg_eax,imm [-i: o32 1d id]
SBB reg_rax,sbytedword [mi: o64 83 /3 ib,s]
SBB reg_rax,imm [-i: o64 1d id,s]
SBB rm8,imm [mi: hle 80 /3 ib]
SBB rm16,sbyteword [mi: hle o16 83 /3 ib,s]
SBB rm16,imm [mi: hle o16 81 /3 iw]
SBB rm32,sbytedword [mi: hle o32 83 /3 ib,s]
SBB rm32,imm [mi: hle o32 81 /3 id]
SBB rm64,sbytedword [mi: hle o64 83 /3 ib,s]
SBB rm64,imm [mi: hle o64 81 /3 id,s]
SBB mem,imm8 [mi: hle 80 /3 ib]
SBB mem,sbyteword16 [mi: hle o16 83 /3 ib,s]
SBB mem,imm16 [mi: hle o16 81 /3 iw]
SBB mem,sbytedword32 [mi: hle o32 83 /3 ib,s]
SBB mem,imm32 [mi: hle o32 81 /3 id]
SCASB void [ repe ae]
SCASD void [ repe o32 af]
SCASQ void [ repe o64 af]
SCASW void [ repe o16 af]
SFENCE void [ np 0f ae f8]
SGDT mem [m: 0f 01 /0]
SHL rm8,unity [m-: d0 /4]
SHL rm8,reg_cl [m-: d2 /4]
SHL rm8,imm8 [mi: c0 /4 ib,u]
SHL rm16,unity [m-: o16 d1 /4]
SHL rm16,reg_cl [m-: o16 d3 /4]
SHL rm16,imm8 [mi: o16 c1 /4 ib,u]
SHL rm32,unity [m-: o32 d1 /4]
SHL rm32,reg_cl [m-: o32 d3 /4]
SHL rm32,imm8 [mi: o32 c1 /4 ib,u]
SHL rm64,unity [m-: o64 d1 /4]
SHL rm64,reg_cl [m-: o64 d3 /4]
SHL rm64,imm8 [mi: o64 c1 /4 ib,u]
SHLD mem,reg16,imm [mri: o16 0f a4 /r ib,u]
SHLD reg16,reg16,imm [mri: o16 0f a4 /r ib,u]
SHLD mem,reg32,imm [mri: o32 0f a4 /r ib,u]
SHLD reg32,reg32,imm [mri: o32 0f a4 /r ib,u]
SHLD mem,reg64,imm [mri: o64 0f a4 /r ib,u]
SHLD reg64,reg64,imm [mri: o64 0f a4 /r ib,u]
SHLD mem,reg16,reg_cl [mr-: o16 0f a5 /r]
SHLD reg16,reg16,reg_cl [mr-: o16 0f a5 /r]
SHLD mem,reg32,reg_cl [mr-: o32 0f a5 /r]
SHLD reg32,reg32,reg_cl [mr-: o32 0f a5 /r]
SHLD mem,reg64,reg_cl [mr-: o64 0f a5 /r]
SHLD reg64,reg64,reg_cl [mr-: o64 0f a5 /r]
SHR rm8,unity [m-: d0 /5]
SHR rm8,reg_cl [m-: d2 /5]
SHR rm8,imm8 [mi: c0 /5 ib,u]
SHR rm16,unity [m-: o16 d1 /5]
SHR rm16,reg_cl [m-: o16 d3 /5]
SHR rm16,imm8 [mi: o16 c1 /5 ib,u]
SHR rm32,unity [m-: o32 d1 /5]
SHR rm32,reg_cl [m-: o32 d3 /5]
SHR rm32,imm8 [mi: o32 c1 /5 ib,u]
SHR rm64,unity [m-: o64 d1 /5]
SHR rm64,reg_cl [m-: o64 d3 /5]
SHR rm64,imm8 [mi: o64 c1 /5 ib,u]
SHRD mem,reg16,imm [mri: o16 0f ac /r ib,u]
SHRD reg16,reg16,imm [mri: o16 0f ac /r ib,u]
SHRD mem,reg32,imm [mri: o32 0f ac /r ib,u]
SHRD reg32,reg32,imm [mri: o32 0f ac /r ib,u]
SHRD mem,reg64,imm [mri: o64 0f ac /r ib,u]
SHRD reg64,reg64,imm [mri: o64 0f ac /r ib,u]
SHRD mem,reg16,reg_cl [mr-: o16 0f ad /r]
SHRD reg16,reg16,reg_cl [mr-: o16 0f ad /r]
SHRD mem,reg32,reg_cl [mr-: o32 0f ad /r]
SHRD reg32,reg32,reg_cl [mr-: o32 0f ad /r]
SHRD mem,reg64,reg_cl [mr-: o64 0f ad /r]
SHRD reg64,reg64,reg_cl [mr-: o64 0f ad /r]
SIDT mem [m: 0f 01 /1]
SLDT mem [m: 0f 00 /0]
SLDT mem16 [m: 0f 00 /0]
SLDT reg16 [m: o16 0f 00 /0]
SLDT reg32 [m: o32 0f 00 /0]
SLDT reg64 [m: o64nw 0f 00 /0]
SLDT reg64 [m: o64 0f 00 /0]
SKINIT void [ 0f 01 de]
SMI void [ f1]
SMINT void [ 0f 38]
; Older Cyrix chips had this; they had to move due to conflict with MMX
SMSW mem [m: 0f 01 /4]
SMSW mem16 [m: 0f 01 /4]
SMSW reg16 [m: o16 0f 01 /4]
SMSW reg32 [m: o32 0f 01 /4]
SMSW reg64 [m: o64 0f 01 /4]
STC void [ f9]
STD void [ fd]
STI void [ fb]
STOSB void [ aa]
STOSD void [ o32 ab]
STOSQ void [ o64 ab]
STOSW void [ o16 ab]
STR mem [m: 0f 00 /1]
STR mem16 [m: 0f 00 /1]
STR reg16 [m: o16 0f 00 /1]
STR reg32 [m: o32 0f 00 /1]
STR reg64 [m: o64 0f 00 /1]
SUB mem,reg8 [mr: hle 28 /r]
SUB reg8,reg8 [mr: 28 /r]
SUB mem,reg16 [mr: hle o16 29 /r]
SUB reg16,reg16 [mr: o16 29 /r]
SUB mem,reg32 [mr: hle o32 29 /r]
SUB reg32,reg32 [mr: o32 29 /r]
SUB mem,reg64 [mr: hle o64 29 /r]
SUB reg64,reg64 [mr: o64 29 /r]
SUB reg8,mem [rm: 2a /r]
SUB reg8,reg8 [rm: 2a /r]
SUB reg16,mem [rm: o16 2b /r]
SUB reg16,reg16 [rm: o16 2b /r]
SUB reg32,mem [rm: o32 2b /r]
SUB reg32,reg32 [rm: o32 2b /r]
SUB reg64,mem [rm: o64 2b /r]
SUB reg64,reg64 [rm: o64 2b /r]
SUB rm16,imm8 [mi: hle o16 83 /5 ib,s]
SUB rm32,imm8 [mi: hle o32 83 /5 ib,s]
SUB rm64,imm8 [mi: hle o64 83 /5 ib,s]
SUB reg_al,imm [-i: 2c ib]
SUB reg_ax,sbyteword [mi: o16 83 /5 ib,s]
SUB reg_ax,imm [-i: o16 2d iw]
SUB reg_eax,sbytedword [mi: o32 83 /5 ib,s]
SUB reg_eax,imm [-i: o32 2d id]
SUB reg_rax,sbytedword [mi: o64 83 /5 ib,s]
SUB reg_rax,imm [-i: o64 2d id,s]
SUB rm8,imm [mi: hle 80 /5 ib]
SUB rm16,sbyteword [mi: hle o16 83 /5 ib,s]
SUB rm16,imm [mi: hle o16 81 /5 iw]
SUB rm32,sbytedword [mi: hle o32 83 /5 ib,s]
SUB rm32,imm [mi: hle o32 81 /5 id]
SUB rm64,sbytedword [mi: hle o64 83 /5 ib,s]
SUB rm64,imm [mi: hle o64 81 /5 id,s]
SUB mem,imm8 [mi: hle 80 /5 ib]
SUB mem,sbyteword16 [mi: hle o16 83 /5 ib,s]
SUB mem,imm16 [mi: hle o16 81 /5 iw]
SUB mem,sbytedword32 [mi: hle o32 83 /5 ib,s]
SUB mem,imm32 [mi: hle o32 81 /5 id]
SVDC mem80,reg_sreg [mr: 0f 78 /r]
SVLDT mem80 [m: 0f 7a /0]
SVTS mem80 [m: 0f 7c /0]
SWAPGS void [ 0f 01 f8]
SYSCALL void [ 0f 05]
SYSENTER void [ 0f 34]
SYSEXIT void [ 0f 35]
SYSRET void [ 0f 07]
TEST mem,reg8 [mr: 84 /r]
TEST reg8,reg8 [mr: 84 /r]
TEST mem,reg16 [mr: o16 85 /r]
TEST reg16,reg16 [mr: o16 85 /r]
TEST mem,reg32 [mr: o32 85 /r]
TEST reg32,reg32 [mr: o32 85 /r]
TEST mem,reg64 [mr: o64 85 /r]
TEST reg64,reg64 [mr: o64 85 /r]
TEST reg8,mem [rm: 84 /r]
TEST reg16,mem [rm: o16 85 /r]
TEST reg32,mem [rm: o32 85 /r]
TEST reg64,mem [rm: o64 85 /r]
TEST reg_al,imm [-i: a8 ib]
TEST reg_ax,imm [-i: o16 a9 iw]
TEST reg_eax,imm [-i: o32 a9 id]
TEST reg_rax,imm [-i: o64 a9 id,s]
TEST rm8,imm [mi: f6 /0 ib]
TEST rm16,imm [mi: o16 f7 /0 iw]
TEST rm32,imm [mi: o32 f7 /0 id]
TEST rm64,imm [mi: o64 f7 /0 id,s]
TEST mem,imm8 [mi: f6 /0 ib]
TEST mem,imm16 [mi: o16 f7 /0 iw]
TEST mem,imm32 [mi: o32 f7 /0 id]
UD0 reg16,rm16 [rm: o16 0f ff /r]
UD0 reg32,rm32 [rm: o32 0f ff /r]
UD0 reg64,rm64 [rm: o64 0f ff /r]
UD1 reg,rm16 [rm: o16 0f b9 /r]
UD1 reg,rm32 [rm: o32 0f b9 /r]
UD1 reg,rm64 [rm: o64 0f b9 /r]
UD1 void [ 0f b9]
UD2B void [ 0f b9]
UD2B reg,rm16 [rm: o16 0f b9 /r]
UD2B reg,rm32 [rm: o32 0f b9 /r]
UD2B reg,rm64 [rm: o64 0f b9 /r]
UD2 void [ 0f 0b]
UD2A void [ 0f 0b]
UMOV mem,reg8 [mr: np 0f 10 /r]
UMOV reg8,reg8 [mr: np 0f 10 /r]
UMOV mem,reg16 [mr: np o16 0f 11 /r]
UMOV reg16,reg16 [mr: np o16 0f 11 /r]
UMOV mem,reg32 [mr: np o32 0f 11 /r]
UMOV reg32,reg32 [mr: np o32 0f 11 /r]
UMOV reg8,mem [rm: np 0f 12 /r]
UMOV reg8,reg8 [rm: np 0f 12 /r]
UMOV reg16,mem [rm: np o16 0f 13 /r]
UMOV reg16,reg16 [rm: np o16 0f 13 /r]
UMOV reg32,mem [rm: np o32 0f 13 /r]
UMOV reg32,reg32 [rm: np o32 0f 13 /r]
VERR mem [m: 0f 00 /4]
VERR mem16 [m: 0f 00 /4]
VERR reg16 [m: 0f 00 /4]
VERW mem [m: 0f 00 /5]
VERW mem16 [m: 0f 00 /5]
VERW reg16 [m: 0f 00 /5]
FWAIT void [ wait]
WBINVD void [ 0f 09]
WRSHR rm32 [m: o32 0f 37 /0]
WRMSR void [ 0f 30]
XADD mem,reg8 [mr: hle 0f c0 /r]
XADD reg8,reg8 [mr: 0f c0 /r]
XADD mem,reg16 [mr: hle o16 0f c1 /r]
XADD reg16,reg16 [mr: o16 0f c1 /r]
XADD mem,reg32 [mr: hle o32 0f c1 /r]
XADD reg32,reg32 [mr: o32 0f c1 /r]
XADD mem,reg64 [mr: hle o64 0f c1 /r]
XADD reg64,reg64 [mr: o64 0f c1 /r]
XBTS reg16,mem [rm: o16 0f a6 /r]
XBTS reg16,reg16 [rm: o16 0f a6 /r]
XBTS reg32,mem [rm: o32 0f a6 /r]
XBTS reg32,reg32 [rm: o32 0f a6 /r]
XCHG reg_ax,reg16 [-r: o16 90+r]
XCHG reg_eax,reg32na [-r: o32 90+r]
XCHG reg_rax,reg64 [-r: o64 90+r]
XCHG reg16,reg_ax [r-: o16 90+r]
XCHG reg32na,reg_eax [r-: o32 90+r]
XCHG reg64,reg_rax [r-: o64 90+r]
; "xchg eax,eax" is *not* a NOP.
XCHG reg8,mem [rm: hlenl 86 /r]
XCHG reg8,reg8 [rm: 86 /r]
XCHG reg16,mem [rm: hlenl o16 87 /r]
XCHG reg16,reg16 [rm: o16 87 /r]
XCHG reg32,mem [rm: hlenl o32 87 /r]
XCHG reg32,reg32 [rm: o32 87 /r]
XCHG reg64,mem [rm: hlenl o64 87 /r]
XCHG reg64,reg64 [rm: o64 87 /r]
XCHG mem,reg8 [mr: hlenl 86 /r]
XCHG reg8,reg8 [mr: 86 /r]
XCHG mem,reg16 [mr: hlenl o16 87 /r]
XCHG reg16,reg16 [mr: o16 87 /r]
XCHG mem,reg32 [mr: hlenl o32 87 /r]
XCHG reg32,reg32 [mr: o32 87 /r]
XCHG mem,reg64 [mr: hlenl o64 87 /r]
XCHG reg64,reg64 [mr: o64 87 /r]
XLATB void [ d7]
XLAT void [ d7]
XOR mem,reg8 [mr: hle 30 /r]
XOR reg8,reg8 [mr: 30 /r]
XOR mem,reg16 [mr: hle o16 31 /r]
XOR reg16,reg16 [mr: o16 31 /r]
XOR mem,reg32 [mr: hle o32 31 /r]
XOR reg32,reg32 [mr: o32 31 /r]
XOR mem,reg64 [mr: hle o64 31 /r]
XOR reg64,reg64 [mr: o64 31 /r]
XOR reg8,mem [rm: 32 /r]
XOR reg8,reg8 [rm: 32 /r]
XOR reg16,mem [rm: o16 33 /r]
XOR reg16,reg16 [rm: o16 33 /r]
XOR reg32,mem [rm: o32 33 /r]
XOR reg32,reg32 [rm: o32 33 /r]
XOR reg64,mem [rm: o64 33 /r]
XOR reg64,reg64 [rm: o64 33 /r]
XOR rm16,imm8 [mi: hle o16 83 /6 ib,s]
XOR rm32,imm8 [mi: hle o32 83 /6 ib,s]
XOR rm64,imm8 [mi: hle o64 83 /6 ib,s]
XOR reg_al,imm [-i: 34 ib]
XOR reg_ax,sbyteword [mi: o16 83 /6 ib,s]
XOR reg_ax,imm [-i: o16 35 iw]
XOR reg_eax,sbytedword [mi: o32 83 /6 ib,s]
XOR reg_eax,imm [-i: o32 35 id]
XOR reg_rax,sbytedword [mi: o64 83 /6 ib,s]
XOR reg_rax,imm [-i: o64 35 id,s]
XOR rm8,imm [mi: hle 80 /6 ib]
XOR rm16,sbyteword [mi: hle o16 83 /6 ib,s]
XOR rm16,imm [mi: hle o16 81 /6 iw]
XOR rm32,sbytedword [mi: hle o32 83 /6 ib,s]
XOR rm32,imm [mi: hle o32 81 /6 id]
XOR rm64,sbytedword [mi: hle o64 83 /6 ib,s]
XOR rm64,imm [mi: hle o64 81 /6 id,s]
XOR mem,imm8 [mi: hle 80 /6 ib]
XOR mem,sbyteword16 [mi: hle o16 83 /6 ib,s]
XOR mem,imm16 [mi: hle o16 81 /6 iw]
XOR mem,sbytedword32 [mi: hle o32 83 /6 ib,s]
XOR mem,imm32 [mi: hle o32 81 /6 id]
CMOVcc reg16,mem [rm: o16 0f 40+c /r]
CMOVcc reg16,reg16 [rm: o16 0f 40+c /r]
CMOVcc reg32,mem [rm: o32 0f 40+c /r]
CMOVcc reg32,reg32 [rm: o32 0f 40+c /r]
CMOVcc reg64,mem [rm: o64 0f 40+c /r]
CMOVcc reg64,reg64 [rm: o64 0f 40+c /r]
Jcc imm|near [i: odf 0f 80+c rel]
Jcc imm64|near [i: o64nw 0f 80+c rel]
Jcc imm|short [i: 70+c rel8]
Jcc imm [i: jcc8 70+c rel8]
Jcc imm [i: 0f 80+c rel]
;? Jcc imm [i: 71+c jlen e9 rel]
Jcc imm [i: 70+c rel8]

SETcc mem [m: 0f 90+c /0]
SETcc reg8 [m: 0f 90+c /0]

POPCNT reg16,rm16 [rm: o16 f3i 0f b8 /r]
POPCNT reg32,rm32 [rm: o32 f3i 0f b8 /r]
POPCNT reg64,rm64 [rm: o64 f3i 0f b8 /r]
