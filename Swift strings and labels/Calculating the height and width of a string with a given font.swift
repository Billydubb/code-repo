    
//Height

    func heightOf(_ string: String, usingFont font: UIFont) -> CGFloat {
        let fontAttributes = [NSFontAttributeName: font]
        let size = string.size(attributes: fontAttributes)
        return size.height
    }


//Width
	func widthOfString(_ string: String, usingFont font: UIFont) -> CGFloat {
        let fontAttributes = [NSFontAttributeName: font]
        let size = string.size(attributes: fontAttributes)
        return size.width
    }    