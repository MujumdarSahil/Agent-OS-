import ReactMarkdown from 'react-markdown'

interface SafeMarkdownProps {
  content: string
  className?: string
}

export default function SafeMarkdown({ content, className = '' }: SafeMarkdownProps) {
  return (
    <div className={`safe-markdown ${className}`}>
      <ReactMarkdown
        components={{
          // Remote images are strictly blocked to prevent tracking / exfiltration
          img: ({ src, alt, ...props }) => {
            if (!src || src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//')) {
              return (
                <span
                  style={{
                    display: 'inline-block',
                    padding: '2px 8px',
                    margin: '2px 0',
                    fontSize: '12px',
                    color: 'var(--accent-red, #ef4444)',
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px dashed var(--accent-red, #ef4444)',
                    borderRadius: '4px',
                  }}
                >
                  [Remote image blocked: {alt || 'image'}]
                </span>
              )
            }
            return <img src={src} alt={alt} {...props} />
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  )
}
