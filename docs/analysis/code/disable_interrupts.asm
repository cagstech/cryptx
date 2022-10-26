; helper macro for saving the interrupt state, then disabling interrupts
macro save_interrupts?
    ld a,i
    push af
    pop bc
    ld (.__interrupt_state),bc
    di
end macro

; helper macro for restoring the interrupt state
macro restore_interrupts? parent
    ld bc,0
parent.__interrupt_state = $-3
    push bc
    pop af
    ret po
    ei
end macro
