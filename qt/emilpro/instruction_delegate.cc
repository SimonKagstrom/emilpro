#include "instruction_delegate.hh"

#include <qpainter.h>
#include <qstyleoption.h>

void
InstructionDelegate::HighlightStrings(std::span<const std::string> highlight_strings)

{
    m_highlight_strings.clear();
    for (const auto& str : highlight_strings)
    {
        m_highlight_strings.push_back(QString::fromStdString(str));
    }
}

void
InstructionDelegate::paint(QPainter* painter,
                           const QStyleOptionViewItem& option,
                           const QModelIndex& index) const
{
    constexpr auto colors = std::array
    {
        "red",
        "green",
        "blue",
        "cyan",
    };

    QStyleOptionViewItem options = option;
    initStyleOption(&options, index);

    auto encoding = options.text;
    auto color_index = 0;
    for (const auto& str : m_highlight_strings)
    {
        QString color = colors[color_index];

        encoding.replace(str, "<font color=\"" + color + "\">" + str + "</font>");
        // Reuse the first color if more than 4 entries
        color_index = (color_index + 1) % colors.size();
    }

    painter->save();

    QTextDocument doc;
    doc.setDefaultFont(options.font);
    doc.setHtml(encoding);

    options.text = "";
    options.widget->style()->drawControl(QStyle::CE_ItemViewItem, &options, painter);

    painter->translate(options.rect.left(), options.rect.top());
    QRect clip(0, 0, options.rect.width(), options.rect.height());
    doc.drawContents(painter, clip);

    painter->restore();
}

QSize
InstructionDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    return QSize();
}