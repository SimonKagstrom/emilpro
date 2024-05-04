// From https://stackoverflow.com/questions/1956542/how-to-make-item-view-render-rich-html-text-in-qt/1956781#1956781
#pragma once

#include "emilpro/i_instruction.hh"

#include <qstyleditemdelegate.h>
#include <qtextdocument.h>

class InstructionDelegate : public QStyledItemDelegate
{
public:
    void HighlightStrings(std::span<const std::string> highlight_strings);

private:
    void paint(QPainter* painter,
               const QStyleOptionViewItem& option,
               const QModelIndex& index) const final;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const final;

    std::vector<QString> m_highlight_strings;
};
