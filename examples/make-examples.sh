#!/usr/bin/env sh
set -e
set -x
STOOL="python3 ../bin/suit-tool"
SRCS=`ls *.json`
rm -f examples.txt
for SRC in $SRCS ; do
    $STOOL create -i $SRC -o $SRC.cbor
    $STOOL sign -m $SRC.cbor -k ../private_key.pem -o signed-$SRC.cbor
    $STOOL parse -m signed-$SRC.cbor > signed-$SRC.txt
    rm -f $SRC.txt
    # echo "$SRC" | sed -e "s/example\([0-9]*\).json/## Example \1:/" > $SRC.txt
    # echo "" >> $SRC.txt
    echo "~~~" >> $SRC.txt
    cat signed-$SRC.txt >> $SRC.txt
    echo "~~~" >> $SRC.txt
    echo "" >> $SRC.txt
    echo "Total size of manifest without COSE authentication object: " `stat -f "%z" $SRC.cbor`>> $SRC.txt
    echo "" >> $SRC.txt
    echo "Manifest:">> $SRC.txt
    echo "" >> $SRC.txt
    echo "~~~" >> $SRC.txt
    xxd -ps $SRC.cbor>> $SRC.txt
    echo "~~~" >> $SRC.txt
    echo "" >> $SRC.txt
    echo "Total size of manifest with COSE authentication object: " `stat -f "%z" signed-$SRC.cbor`>> $SRC.txt
    echo "" >> $SRC.txt
    echo "Manifest with COSE authentication object:">> $SRC.txt
    echo "" >> $SRC.txt
    echo "~~~" >> $SRC.txt
    xxd -ps signed-$SRC.cbor>> $SRC.txt
    echo "~~~" >> $SRC.txt
    echo "" >> $SRC.txt
    cat $SRC.txt >> examples.txt
done
