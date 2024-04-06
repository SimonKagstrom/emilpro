#include "qhexeditdatawriter.h"

QHexEditDataWriter::QHexEditDataWriter(QHexEditData *hexeditdata, QObject *parent): QObject(parent), _hexeditdata(hexeditdata)
{

}

const QHexEditData *QHexEditDataWriter::hexEditData() const
{
    return this->_hexeditdata;
}

void QHexEditDataWriter::append(const QByteArray &ba)
{
    this->insert(this->_hexeditdata->length(), ba);
}

void QHexEditDataWriter::insert(qint64 pos, uchar ch)
{
    this->insert(pos, QByteArray().append(ch));
}

void QHexEditDataWriter::insert(qint64 pos, const QByteArray &ba)
{
    QHexEditData::InsertCommand* ic = this->_hexeditdata->internalInsert(pos, ba, QHexEditData::Insert);

    if(ic)
    {
        this->_hexeditdata->recordAction(QHexEditData::Insert, pos + ba.length());
        this->_hexeditdata->_undostack.push(ic);
    }
}

void QHexEditDataWriter::remove(qint64 pos, qint64 len)
{
    QHexEditData::RemoveCommand* rc = this->_hexeditdata->internalRemove(pos, len, QHexEditData::Remove);

    if(rc)
    {
        this->_hexeditdata->recordAction(QHexEditData::Remove, pos);
        this->_hexeditdata->_undostack.push(rc);
    }
}

void QHexEditDataWriter::replace(qint64 pos, uchar b)
{
    this->replace(pos, 1, b);
}

void QHexEditDataWriter::replace(qint64 pos, qint64 len, uchar b)
{
    this->replace(pos, len, QByteArray().append(b));
}

void QHexEditDataWriter::replace(qint64 pos, const QByteArray &ba)
{
    this->replace(pos, ba.length(), ba);
}

void QHexEditDataWriter::replace(qint64 pos, qint64 len, const QByteArray &ba)
{
    if(pos > this->_hexeditdata->length() || ba.isEmpty() || !this->_hexeditdata->modifiedItem(pos))
        return;

    this->_hexeditdata->_undostack.push(new QHexEditData::ReplaceCommand(pos, len, ba, this->_hexeditdata));
    this->_hexeditdata->recordAction(QHexEditData::Replace, pos + ba.length());
}
