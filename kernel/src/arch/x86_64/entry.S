// Trap entry and return, x86_64. Every vector has a stub that pushes an
// error code (0 if the CPU didn't) and its number, then the common entry
// saves the general registers into a TrapFrame (mod.rs) and calls
// trap_entry. From user mode the CPU switched to this CPU's kernel stack
// (TSS.rsp0) first, so the frame ends at its top; syscall_entry builds the
// same frame by hand. Everything leaves by iretq through return_from_trap.

    .pushsection .text, "ax"

// The stubs (generated: the CPU pushes an error code for 8, 10, 11, 12, 13, 14, 17, 21, 29, 30).
isr_0:
    pushq $0
    pushq $0
    jmp common_entry
isr_1:
    pushq $0
    pushq $1
    jmp common_entry
isr_2:
    pushq $0
    pushq $2
    jmp common_entry
isr_3:
    pushq $0
    pushq $3
    jmp common_entry
isr_4:
    pushq $0
    pushq $4
    jmp common_entry
isr_5:
    pushq $0
    pushq $5
    jmp common_entry
isr_6:
    pushq $0
    pushq $6
    jmp common_entry
isr_7:
    pushq $0
    pushq $7
    jmp common_entry
isr_8:
    pushq $8
    jmp common_entry
isr_9:
    pushq $0
    pushq $9
    jmp common_entry
isr_10:
    pushq $10
    jmp common_entry
isr_11:
    pushq $11
    jmp common_entry
isr_12:
    pushq $12
    jmp common_entry
isr_13:
    pushq $13
    jmp common_entry
isr_14:
    pushq $14
    jmp common_entry
isr_15:
    pushq $0
    pushq $15
    jmp common_entry
isr_16:
    pushq $0
    pushq $16
    jmp common_entry
isr_17:
    pushq $17
    jmp common_entry
isr_18:
    pushq $0
    pushq $18
    jmp common_entry
isr_19:
    pushq $0
    pushq $19
    jmp common_entry
isr_20:
    pushq $0
    pushq $20
    jmp common_entry
isr_21:
    pushq $21
    jmp common_entry
isr_22:
    pushq $0
    pushq $22
    jmp common_entry
isr_23:
    pushq $0
    pushq $23
    jmp common_entry
isr_24:
    pushq $0
    pushq $24
    jmp common_entry
isr_25:
    pushq $0
    pushq $25
    jmp common_entry
isr_26:
    pushq $0
    pushq $26
    jmp common_entry
isr_27:
    pushq $0
    pushq $27
    jmp common_entry
isr_28:
    pushq $0
    pushq $28
    jmp common_entry
isr_29:
    pushq $29
    jmp common_entry
isr_30:
    pushq $30
    jmp common_entry
isr_31:
    pushq $0
    pushq $31
    jmp common_entry
isr_32:
    pushq $0
    pushq $32
    jmp common_entry
isr_33:
    pushq $0
    pushq $33
    jmp common_entry
isr_34:
    pushq $0
    pushq $34
    jmp common_entry
isr_35:
    pushq $0
    pushq $35
    jmp common_entry
isr_36:
    pushq $0
    pushq $36
    jmp common_entry
isr_37:
    pushq $0
    pushq $37
    jmp common_entry
isr_38:
    pushq $0
    pushq $38
    jmp common_entry
isr_39:
    pushq $0
    pushq $39
    jmp common_entry
isr_40:
    pushq $0
    pushq $40
    jmp common_entry
isr_41:
    pushq $0
    pushq $41
    jmp common_entry
isr_42:
    pushq $0
    pushq $42
    jmp common_entry
isr_43:
    pushq $0
    pushq $43
    jmp common_entry
isr_44:
    pushq $0
    pushq $44
    jmp common_entry
isr_45:
    pushq $0
    pushq $45
    jmp common_entry
isr_46:
    pushq $0
    pushq $46
    jmp common_entry
isr_47:
    pushq $0
    pushq $47
    jmp common_entry
isr_48:
    pushq $0
    pushq $48
    jmp common_entry
isr_49:
    pushq $0
    pushq $49
    jmp common_entry
isr_50:
    pushq $0
    pushq $50
    jmp common_entry
isr_51:
    pushq $0
    pushq $51
    jmp common_entry
isr_52:
    pushq $0
    pushq $52
    jmp common_entry
isr_53:
    pushq $0
    pushq $53
    jmp common_entry
isr_54:
    pushq $0
    pushq $54
    jmp common_entry
isr_55:
    pushq $0
    pushq $55
    jmp common_entry
isr_56:
    pushq $0
    pushq $56
    jmp common_entry
isr_57:
    pushq $0
    pushq $57
    jmp common_entry
isr_58:
    pushq $0
    pushq $58
    jmp common_entry
isr_59:
    pushq $0
    pushq $59
    jmp common_entry
isr_60:
    pushq $0
    pushq $60
    jmp common_entry
isr_61:
    pushq $0
    pushq $61
    jmp common_entry
isr_62:
    pushq $0
    pushq $62
    jmp common_entry
isr_63:
    pushq $0
    pushq $63
    jmp common_entry
isr_64:
    pushq $0
    pushq $64
    jmp common_entry
isr_65:
    pushq $0
    pushq $65
    jmp common_entry
isr_66:
    pushq $0
    pushq $66
    jmp common_entry
isr_67:
    pushq $0
    pushq $67
    jmp common_entry
isr_68:
    pushq $0
    pushq $68
    jmp common_entry
isr_69:
    pushq $0
    pushq $69
    jmp common_entry
isr_70:
    pushq $0
    pushq $70
    jmp common_entry
isr_71:
    pushq $0
    pushq $71
    jmp common_entry
isr_72:
    pushq $0
    pushq $72
    jmp common_entry
isr_73:
    pushq $0
    pushq $73
    jmp common_entry
isr_74:
    pushq $0
    pushq $74
    jmp common_entry
isr_75:
    pushq $0
    pushq $75
    jmp common_entry
isr_76:
    pushq $0
    pushq $76
    jmp common_entry
isr_77:
    pushq $0
    pushq $77
    jmp common_entry
isr_78:
    pushq $0
    pushq $78
    jmp common_entry
isr_79:
    pushq $0
    pushq $79
    jmp common_entry
isr_80:
    pushq $0
    pushq $80
    jmp common_entry
isr_81:
    pushq $0
    pushq $81
    jmp common_entry
isr_82:
    pushq $0
    pushq $82
    jmp common_entry
isr_83:
    pushq $0
    pushq $83
    jmp common_entry
isr_84:
    pushq $0
    pushq $84
    jmp common_entry
isr_85:
    pushq $0
    pushq $85
    jmp common_entry
isr_86:
    pushq $0
    pushq $86
    jmp common_entry
isr_87:
    pushq $0
    pushq $87
    jmp common_entry
isr_88:
    pushq $0
    pushq $88
    jmp common_entry
isr_89:
    pushq $0
    pushq $89
    jmp common_entry
isr_90:
    pushq $0
    pushq $90
    jmp common_entry
isr_91:
    pushq $0
    pushq $91
    jmp common_entry
isr_92:
    pushq $0
    pushq $92
    jmp common_entry
isr_93:
    pushq $0
    pushq $93
    jmp common_entry
isr_94:
    pushq $0
    pushq $94
    jmp common_entry
isr_95:
    pushq $0
    pushq $95
    jmp common_entry
isr_96:
    pushq $0
    pushq $96
    jmp common_entry
isr_97:
    pushq $0
    pushq $97
    jmp common_entry
isr_98:
    pushq $0
    pushq $98
    jmp common_entry
isr_99:
    pushq $0
    pushq $99
    jmp common_entry
isr_100:
    pushq $0
    pushq $100
    jmp common_entry
isr_101:
    pushq $0
    pushq $101
    jmp common_entry
isr_102:
    pushq $0
    pushq $102
    jmp common_entry
isr_103:
    pushq $0
    pushq $103
    jmp common_entry
isr_104:
    pushq $0
    pushq $104
    jmp common_entry
isr_105:
    pushq $0
    pushq $105
    jmp common_entry
isr_106:
    pushq $0
    pushq $106
    jmp common_entry
isr_107:
    pushq $0
    pushq $107
    jmp common_entry
isr_108:
    pushq $0
    pushq $108
    jmp common_entry
isr_109:
    pushq $0
    pushq $109
    jmp common_entry
isr_110:
    pushq $0
    pushq $110
    jmp common_entry
isr_111:
    pushq $0
    pushq $111
    jmp common_entry
isr_112:
    pushq $0
    pushq $112
    jmp common_entry
isr_113:
    pushq $0
    pushq $113
    jmp common_entry
isr_114:
    pushq $0
    pushq $114
    jmp common_entry
isr_115:
    pushq $0
    pushq $115
    jmp common_entry
isr_116:
    pushq $0
    pushq $116
    jmp common_entry
isr_117:
    pushq $0
    pushq $117
    jmp common_entry
isr_118:
    pushq $0
    pushq $118
    jmp common_entry
isr_119:
    pushq $0
    pushq $119
    jmp common_entry
isr_120:
    pushq $0
    pushq $120
    jmp common_entry
isr_121:
    pushq $0
    pushq $121
    jmp common_entry
isr_122:
    pushq $0
    pushq $122
    jmp common_entry
isr_123:
    pushq $0
    pushq $123
    jmp common_entry
isr_124:
    pushq $0
    pushq $124
    jmp common_entry
isr_125:
    pushq $0
    pushq $125
    jmp common_entry
isr_126:
    pushq $0
    pushq $126
    jmp common_entry
isr_127:
    pushq $0
    pushq $127
    jmp common_entry
isr_128:
    pushq $0
    pushq $128
    jmp common_entry
isr_129:
    pushq $0
    pushq $129
    jmp common_entry
isr_130:
    pushq $0
    pushq $130
    jmp common_entry
isr_131:
    pushq $0
    pushq $131
    jmp common_entry
isr_132:
    pushq $0
    pushq $132
    jmp common_entry
isr_133:
    pushq $0
    pushq $133
    jmp common_entry
isr_134:
    pushq $0
    pushq $134
    jmp common_entry
isr_135:
    pushq $0
    pushq $135
    jmp common_entry
isr_136:
    pushq $0
    pushq $136
    jmp common_entry
isr_137:
    pushq $0
    pushq $137
    jmp common_entry
isr_138:
    pushq $0
    pushq $138
    jmp common_entry
isr_139:
    pushq $0
    pushq $139
    jmp common_entry
isr_140:
    pushq $0
    pushq $140
    jmp common_entry
isr_141:
    pushq $0
    pushq $141
    jmp common_entry
isr_142:
    pushq $0
    pushq $142
    jmp common_entry
isr_143:
    pushq $0
    pushq $143
    jmp common_entry
isr_144:
    pushq $0
    pushq $144
    jmp common_entry
isr_145:
    pushq $0
    pushq $145
    jmp common_entry
isr_146:
    pushq $0
    pushq $146
    jmp common_entry
isr_147:
    pushq $0
    pushq $147
    jmp common_entry
isr_148:
    pushq $0
    pushq $148
    jmp common_entry
isr_149:
    pushq $0
    pushq $149
    jmp common_entry
isr_150:
    pushq $0
    pushq $150
    jmp common_entry
isr_151:
    pushq $0
    pushq $151
    jmp common_entry
isr_152:
    pushq $0
    pushq $152
    jmp common_entry
isr_153:
    pushq $0
    pushq $153
    jmp common_entry
isr_154:
    pushq $0
    pushq $154
    jmp common_entry
isr_155:
    pushq $0
    pushq $155
    jmp common_entry
isr_156:
    pushq $0
    pushq $156
    jmp common_entry
isr_157:
    pushq $0
    pushq $157
    jmp common_entry
isr_158:
    pushq $0
    pushq $158
    jmp common_entry
isr_159:
    pushq $0
    pushq $159
    jmp common_entry
isr_160:
    pushq $0
    pushq $160
    jmp common_entry
isr_161:
    pushq $0
    pushq $161
    jmp common_entry
isr_162:
    pushq $0
    pushq $162
    jmp common_entry
isr_163:
    pushq $0
    pushq $163
    jmp common_entry
isr_164:
    pushq $0
    pushq $164
    jmp common_entry
isr_165:
    pushq $0
    pushq $165
    jmp common_entry
isr_166:
    pushq $0
    pushq $166
    jmp common_entry
isr_167:
    pushq $0
    pushq $167
    jmp common_entry
isr_168:
    pushq $0
    pushq $168
    jmp common_entry
isr_169:
    pushq $0
    pushq $169
    jmp common_entry
isr_170:
    pushq $0
    pushq $170
    jmp common_entry
isr_171:
    pushq $0
    pushq $171
    jmp common_entry
isr_172:
    pushq $0
    pushq $172
    jmp common_entry
isr_173:
    pushq $0
    pushq $173
    jmp common_entry
isr_174:
    pushq $0
    pushq $174
    jmp common_entry
isr_175:
    pushq $0
    pushq $175
    jmp common_entry
isr_176:
    pushq $0
    pushq $176
    jmp common_entry
isr_177:
    pushq $0
    pushq $177
    jmp common_entry
isr_178:
    pushq $0
    pushq $178
    jmp common_entry
isr_179:
    pushq $0
    pushq $179
    jmp common_entry
isr_180:
    pushq $0
    pushq $180
    jmp common_entry
isr_181:
    pushq $0
    pushq $181
    jmp common_entry
isr_182:
    pushq $0
    pushq $182
    jmp common_entry
isr_183:
    pushq $0
    pushq $183
    jmp common_entry
isr_184:
    pushq $0
    pushq $184
    jmp common_entry
isr_185:
    pushq $0
    pushq $185
    jmp common_entry
isr_186:
    pushq $0
    pushq $186
    jmp common_entry
isr_187:
    pushq $0
    pushq $187
    jmp common_entry
isr_188:
    pushq $0
    pushq $188
    jmp common_entry
isr_189:
    pushq $0
    pushq $189
    jmp common_entry
isr_190:
    pushq $0
    pushq $190
    jmp common_entry
isr_191:
    pushq $0
    pushq $191
    jmp common_entry
isr_192:
    pushq $0
    pushq $192
    jmp common_entry
isr_193:
    pushq $0
    pushq $193
    jmp common_entry
isr_194:
    pushq $0
    pushq $194
    jmp common_entry
isr_195:
    pushq $0
    pushq $195
    jmp common_entry
isr_196:
    pushq $0
    pushq $196
    jmp common_entry
isr_197:
    pushq $0
    pushq $197
    jmp common_entry
isr_198:
    pushq $0
    pushq $198
    jmp common_entry
isr_199:
    pushq $0
    pushq $199
    jmp common_entry
isr_200:
    pushq $0
    pushq $200
    jmp common_entry
isr_201:
    pushq $0
    pushq $201
    jmp common_entry
isr_202:
    pushq $0
    pushq $202
    jmp common_entry
isr_203:
    pushq $0
    pushq $203
    jmp common_entry
isr_204:
    pushq $0
    pushq $204
    jmp common_entry
isr_205:
    pushq $0
    pushq $205
    jmp common_entry
isr_206:
    pushq $0
    pushq $206
    jmp common_entry
isr_207:
    pushq $0
    pushq $207
    jmp common_entry
isr_208:
    pushq $0
    pushq $208
    jmp common_entry
isr_209:
    pushq $0
    pushq $209
    jmp common_entry
isr_210:
    pushq $0
    pushq $210
    jmp common_entry
isr_211:
    pushq $0
    pushq $211
    jmp common_entry
isr_212:
    pushq $0
    pushq $212
    jmp common_entry
isr_213:
    pushq $0
    pushq $213
    jmp common_entry
isr_214:
    pushq $0
    pushq $214
    jmp common_entry
isr_215:
    pushq $0
    pushq $215
    jmp common_entry
isr_216:
    pushq $0
    pushq $216
    jmp common_entry
isr_217:
    pushq $0
    pushq $217
    jmp common_entry
isr_218:
    pushq $0
    pushq $218
    jmp common_entry
isr_219:
    pushq $0
    pushq $219
    jmp common_entry
isr_220:
    pushq $0
    pushq $220
    jmp common_entry
isr_221:
    pushq $0
    pushq $221
    jmp common_entry
isr_222:
    pushq $0
    pushq $222
    jmp common_entry
isr_223:
    pushq $0
    pushq $223
    jmp common_entry
isr_224:
    pushq $0
    pushq $224
    jmp common_entry
isr_225:
    pushq $0
    pushq $225
    jmp common_entry
isr_226:
    pushq $0
    pushq $226
    jmp common_entry
isr_227:
    pushq $0
    pushq $227
    jmp common_entry
isr_228:
    pushq $0
    pushq $228
    jmp common_entry
isr_229:
    pushq $0
    pushq $229
    jmp common_entry
isr_230:
    pushq $0
    pushq $230
    jmp common_entry
isr_231:
    pushq $0
    pushq $231
    jmp common_entry
isr_232:
    pushq $0
    pushq $232
    jmp common_entry
isr_233:
    pushq $0
    pushq $233
    jmp common_entry
isr_234:
    pushq $0
    pushq $234
    jmp common_entry
isr_235:
    pushq $0
    pushq $235
    jmp common_entry
isr_236:
    pushq $0
    pushq $236
    jmp common_entry
isr_237:
    pushq $0
    pushq $237
    jmp common_entry
isr_238:
    pushq $0
    pushq $238
    jmp common_entry
isr_239:
    pushq $0
    pushq $239
    jmp common_entry
isr_240:
    pushq $0
    pushq $240
    jmp common_entry
isr_241:
    pushq $0
    pushq $241
    jmp common_entry
isr_242:
    pushq $0
    pushq $242
    jmp common_entry
isr_243:
    pushq $0
    pushq $243
    jmp common_entry
isr_244:
    pushq $0
    pushq $244
    jmp common_entry
isr_245:
    pushq $0
    pushq $245
    jmp common_entry
isr_246:
    pushq $0
    pushq $246
    jmp common_entry
isr_247:
    pushq $0
    pushq $247
    jmp common_entry
isr_248:
    pushq $0
    pushq $248
    jmp common_entry
isr_249:
    pushq $0
    pushq $249
    jmp common_entry
isr_250:
    pushq $0
    pushq $250
    jmp common_entry
isr_251:
    pushq $0
    pushq $251
    jmp common_entry
isr_252:
    pushq $0
    pushq $252
    jmp common_entry
isr_253:
    pushq $0
    pushq $253
    jmp common_entry
isr_254:
    pushq $0
    pushq $254
    jmp common_entry
isr_255:
    pushq $0
    pushq $255
    jmp common_entry

// The saved registers, below the vector: orig_rax, rax..r15, padding.
.macro SAVE_REGS orig
    pushq \orig
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8, %rsp
.endm

common_entry:
    // vector at 0(%rsp), error 8, rip 16, cs 24: from user mode, the
    // kernel's GS.
    testb $3, 24(%rsp)
    jz 1f
    swapgs
1:  SAVE_REGS $-1
    // The kernel's flags, none of the program's: DF clear, and AC, which
    // would let the kernel reach user memory past SMAP. (syscall_entry's
    // are SFMASK's.) IF stays clear.
    pushq $2
    popfq
    movq %rsp, %rdi
    call trap_entry
    // fall through

    .globl return_from_trap
return_from_trap:
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $24, %rsp          // orig_rax, vector, error
    // rip at 0(%rsp), cs 8: back to user mode, the user's GS.
    testb $3, 8(%rsp)
    jz 1f
    swapgs
1:  iretq

// return_to_frame_asm(frame): leave through a frame at the top of this
// CPU's stack.
    .globl return_to_frame_asm
return_to_frame_asm:
    movq %rdi, %rsp
    jmp return_from_trap

// syscall: rcx is the user's rip, r11 its rflags; the CPU cleared IF (and
// TF, DF, AC: SFMASK). gs:0 is this CPU's kernel stack top, gs:8 room for
// the user's rsp.
    .globl syscall_entry
syscall_entry:
    swapgs
    movq %rsp, %gs:8
    movq %gs:0, %rsp
    pushq $0x23             // ss
    pushq %gs:8             // rsp
    pushq %r11              // rflags
    pushq $0x2b             // cs
    pushq %rcx              // rip
    pushq $0                // error
    pushq $0x100            // vector: SYSCALL
    SAVE_REGS %rax
    movq %rsp, %rdi
    call trap_entry
    jmp return_from_trap

// load_cpu_tables(gdtr, idtr, tss): this CPU's GDT, IDT and TSS, and its
// segments from the new GDT (code by a far return).
    .globl load_cpu_tables
load_cpu_tables:
    lgdt (%rdi)
    lidt (%rsi)
    pushq $0x08
    leaq 1f(%rip), %rax
    pushq %rax
    lretq
1:  movl $0x10, %eax
    movl %eax, %ds
    movl %eax, %es
    movl %eax, %ss
    xorl %eax, %eax
    movl %eax, %fs
    movl %eax, %gs
    ltr %dx
    ret
    .popsection

// Every stub's address, for the IDT.
    .pushsection .rodata, "a"
    .p2align 3
    .globl isr_table
isr_table:
    .quad isr_0
    .quad isr_1
    .quad isr_2
    .quad isr_3
    .quad isr_4
    .quad isr_5
    .quad isr_6
    .quad isr_7
    .quad isr_8
    .quad isr_9
    .quad isr_10
    .quad isr_11
    .quad isr_12
    .quad isr_13
    .quad isr_14
    .quad isr_15
    .quad isr_16
    .quad isr_17
    .quad isr_18
    .quad isr_19
    .quad isr_20
    .quad isr_21
    .quad isr_22
    .quad isr_23
    .quad isr_24
    .quad isr_25
    .quad isr_26
    .quad isr_27
    .quad isr_28
    .quad isr_29
    .quad isr_30
    .quad isr_31
    .quad isr_32
    .quad isr_33
    .quad isr_34
    .quad isr_35
    .quad isr_36
    .quad isr_37
    .quad isr_38
    .quad isr_39
    .quad isr_40
    .quad isr_41
    .quad isr_42
    .quad isr_43
    .quad isr_44
    .quad isr_45
    .quad isr_46
    .quad isr_47
    .quad isr_48
    .quad isr_49
    .quad isr_50
    .quad isr_51
    .quad isr_52
    .quad isr_53
    .quad isr_54
    .quad isr_55
    .quad isr_56
    .quad isr_57
    .quad isr_58
    .quad isr_59
    .quad isr_60
    .quad isr_61
    .quad isr_62
    .quad isr_63
    .quad isr_64
    .quad isr_65
    .quad isr_66
    .quad isr_67
    .quad isr_68
    .quad isr_69
    .quad isr_70
    .quad isr_71
    .quad isr_72
    .quad isr_73
    .quad isr_74
    .quad isr_75
    .quad isr_76
    .quad isr_77
    .quad isr_78
    .quad isr_79
    .quad isr_80
    .quad isr_81
    .quad isr_82
    .quad isr_83
    .quad isr_84
    .quad isr_85
    .quad isr_86
    .quad isr_87
    .quad isr_88
    .quad isr_89
    .quad isr_90
    .quad isr_91
    .quad isr_92
    .quad isr_93
    .quad isr_94
    .quad isr_95
    .quad isr_96
    .quad isr_97
    .quad isr_98
    .quad isr_99
    .quad isr_100
    .quad isr_101
    .quad isr_102
    .quad isr_103
    .quad isr_104
    .quad isr_105
    .quad isr_106
    .quad isr_107
    .quad isr_108
    .quad isr_109
    .quad isr_110
    .quad isr_111
    .quad isr_112
    .quad isr_113
    .quad isr_114
    .quad isr_115
    .quad isr_116
    .quad isr_117
    .quad isr_118
    .quad isr_119
    .quad isr_120
    .quad isr_121
    .quad isr_122
    .quad isr_123
    .quad isr_124
    .quad isr_125
    .quad isr_126
    .quad isr_127
    .quad isr_128
    .quad isr_129
    .quad isr_130
    .quad isr_131
    .quad isr_132
    .quad isr_133
    .quad isr_134
    .quad isr_135
    .quad isr_136
    .quad isr_137
    .quad isr_138
    .quad isr_139
    .quad isr_140
    .quad isr_141
    .quad isr_142
    .quad isr_143
    .quad isr_144
    .quad isr_145
    .quad isr_146
    .quad isr_147
    .quad isr_148
    .quad isr_149
    .quad isr_150
    .quad isr_151
    .quad isr_152
    .quad isr_153
    .quad isr_154
    .quad isr_155
    .quad isr_156
    .quad isr_157
    .quad isr_158
    .quad isr_159
    .quad isr_160
    .quad isr_161
    .quad isr_162
    .quad isr_163
    .quad isr_164
    .quad isr_165
    .quad isr_166
    .quad isr_167
    .quad isr_168
    .quad isr_169
    .quad isr_170
    .quad isr_171
    .quad isr_172
    .quad isr_173
    .quad isr_174
    .quad isr_175
    .quad isr_176
    .quad isr_177
    .quad isr_178
    .quad isr_179
    .quad isr_180
    .quad isr_181
    .quad isr_182
    .quad isr_183
    .quad isr_184
    .quad isr_185
    .quad isr_186
    .quad isr_187
    .quad isr_188
    .quad isr_189
    .quad isr_190
    .quad isr_191
    .quad isr_192
    .quad isr_193
    .quad isr_194
    .quad isr_195
    .quad isr_196
    .quad isr_197
    .quad isr_198
    .quad isr_199
    .quad isr_200
    .quad isr_201
    .quad isr_202
    .quad isr_203
    .quad isr_204
    .quad isr_205
    .quad isr_206
    .quad isr_207
    .quad isr_208
    .quad isr_209
    .quad isr_210
    .quad isr_211
    .quad isr_212
    .quad isr_213
    .quad isr_214
    .quad isr_215
    .quad isr_216
    .quad isr_217
    .quad isr_218
    .quad isr_219
    .quad isr_220
    .quad isr_221
    .quad isr_222
    .quad isr_223
    .quad isr_224
    .quad isr_225
    .quad isr_226
    .quad isr_227
    .quad isr_228
    .quad isr_229
    .quad isr_230
    .quad isr_231
    .quad isr_232
    .quad isr_233
    .quad isr_234
    .quad isr_235
    .quad isr_236
    .quad isr_237
    .quad isr_238
    .quad isr_239
    .quad isr_240
    .quad isr_241
    .quad isr_242
    .quad isr_243
    .quad isr_244
    .quad isr_245
    .quad isr_246
    .quad isr_247
    .quad isr_248
    .quad isr_249
    .quad isr_250
    .quad isr_251
    .quad isr_252
    .quad isr_253
    .quad isr_254
    .quad isr_255
    .popsection
