
SUITROOT=/suit
PROJROOT=${SUITROOT}/parser_examples
SUITTOOL=${SUITROOT}/bin/suittool

SUITLOADER_DIR=${PROJROOT}/suitloader
SUITLOADER_LIBS=mbed-os
SUITLOADER_LIBS_DIRS=$(patsubst %,${SUITLOADER_DIR}/%,${SUITLOADER_LIBS})
SUITLOADER_LIBS_SRCS=$(patsubst %,${SUITLOADER_DIR}/%.lib,${SUITLOADER_LIBS})
SUITLOADER=${SUITLOADER_DIR}/BUILD/NRF52840_DK/GCC_ARM/suitloader.hex


SUITAPP_DIR=${PROJROOT}/suit-app
SUITAPP_LIBS=mbed-os
SUITAPP_LIBS_DIRS=$(patsubst %,${SUITAPP_DIR}/%,${SUITAPP_LIBS})
SUITAPP_LIBS_SRCS=$(patsubst %,${SUITAPP_DIR}/%.lib,${SUITAPP_LIBS})

SUITAPP_A=${SUITAPP_DIR}/slot_a/suit-app.hex
SUITAPP_B=${SUITAPP_DIR}/slot_b/suit-app.hex

MFST_A=${SUITAPP_DIR}/slot_a/manifest.cbor
MFST_B=${SUITAPP_DIR}/slot_b/manifest.cbor
MFST_SIGNED_A=${SUITAPP_DIR}/slot_a/signed-manifest.cbor
MFST_SIGNED_B=${SUITAPP_DIR}/slot_b/signed-manifest.cbor

SYSIMG=${PROJROOT}/out/suit_merged.hex

.PHONY: all
all: ${SYSIMG}

${SUITLOADER_DIR}/%: ${SUITLOADER_DIR}/%.lib
	cd ${SUITLOADER_DIR} && mbed deploy --depth 1

${SUITAPP_DIR}/%: ${SUITAPP_DIR}/%.lib
	cd ${SUITAPP_DIR} && mbed deploy --depth 1

.PHONY: ${SUITLOADER}
${SUITLOADER}: ${SUITLOADER_LIBS_DIRS} ${PROJROOT}/suitloader/mbed_app.json
	cd ${SUITLOADER_DIR} && mbed compile -t GCC_ARM -m NRF52840_DK

# .PHONY: ${SUITAPP_A}
${SUITAPP_A}: ${SUITAPP_LIBS_DIRS} ${SUITAPP_DIR}/slot-a-manifest.json ${SUITAPP_DIR}/slot_a_app_info.h
	echo "slot_b/*" > ${SUITAPP_DIR}/.mbedignore
	cp ${SUITAPP_DIR}/slot_a_app_info.h ${SUITAPP_DIR}/app_info.h
	cd ${SUITAPP_DIR}/ && mbed compile -t GCC_ARM -m NRF52840_DK --app-config slot-a-config.json --build slot_a

${MFST_A}: ${SUITAPP_DIR}/slot-a-manifest.json ${SUITAPP_A} 
	cd ${SUITAPP_DIR} && python3 ${SUITTOOL} create -i $< -o $@

${MFST_SIGNED_A}: ${MFST_A} ${SUITAPP_DIR}/private_key.pem
	cd ${SUITAPP_DIR} && python3 ${SUITTOOL}  sign -m $< -k ${SUITAPP_DIR}/private_key.pem -o $@

${SUITAPP_B}: ${SUITAPP_LIBS_DIRS}  ${SUITAPP_DIR}/slot_b_app_info.h
	echo "slot_a/*" > ${SUITAPP_DIR}/.mbedignore
	cp ${SUITAPP_DIR}/slot_b_app_info.h ${SUITAPP_DIR}/app_info.h
	cd ${SUITAPP_DIR}/ && mbed compile --app-config slot-b-config.json --build slot_b

${MFST_B}: ${SUITAPP_DIR}/slot-b-manifest.json ${SUITAPP_B} 
	cd ${SUITAPP_DIR} && python3 ${SUITTOOL} create -i $< -o $@

${MFST_SIGNED_B}: ${MFST_B} ${SUITAPP_DIR}/private_key.pem
	cd ${SUITAPP_DIR} && python3 ${SUITTOOL}  sign -m $< -k ${SUITAPP_DIR}/private_key.pem -o $@

${SYSIMG}: ${SUITLOADER} ${MFST_SIGNED_A} ${SUITAPP_A} ${MFST_SIGNED_B} ${SUITAPP_B}
	mkdir -p `dirname ${SYSIMG}`
	srec_cat -Output ${SYSIMG} -Intel -obs=16 \
		${SUITLOADER} -Intel \
		${MFST_SIGNED_A} -Binary -offset 0xA000 \
		${SUITAPP_A} -Intel \
		${MFST_SIGNED_B} -Binary -offset 0x84000 \
		${SUITAPP_B} -Intel


.PHONY: clean
clean:
	rm -rf ${SUITLOADER_DIR}/BUILD
	rm -rf ${SUITAPP_DIR}/slot_a
	rm -rf ${SUITAPP_DIR}/slot_b	